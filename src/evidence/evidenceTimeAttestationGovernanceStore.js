import { createHmac, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  atomicWriteEvidenceJson,
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256,
  strictBase64,
  tenantEvidenceDirectory
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const INDEX_FORMAT = 'basitclaw-evidence-time-attestation-governance-index';
const EVENT_FORMAT = 'basitclaw-evidence-time-attestation-governance-event';
const MODES = new Set(['disabled', 'shared-file']);
const EVENT_TYPES = new Set([
  'attestation_revoked',
  'provider_revoked',
  'key_revoked',
  'attestation_superseded'
]);
const REASON_CODES = new Set([
  'authority_compromise',
  'key_compromise',
  'policy_withdrawn',
  'provider_termination',
  'administrative_error',
  'superseded',
  'legal_direction',
  'other'
]);
const ATTESTATION_ID = /^NTA-[a-f0-9]{32}$/;
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;

export class EvidenceTimeAttestationGovernanceStoreError extends EvidenceStoreError {
  constructor(message = 'The time-attestation governance journal is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceTimeAttestationGovernanceStoreError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_STORE_UNAVAILABLE';
  }
}

export class EvidenceTimeAttestationGovernanceIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Time-attestation governance integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceTimeAttestationGovernanceIntegrityError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_INTEGRITY_FAILED';
  }
}

export class EvidenceTimeAttestationGovernanceRequiredError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('Operationally acceptable time-attestation quorum is required before evidence disposition.', {
      evidenceId,
      ...details
    });
    this.name = 'EvidenceTimeAttestationGovernanceRequiredError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_REQUIRED';
  }
}

export function createEvidenceTimeAttestationGovernanceStore({
  mode = 'disabled',
  requiredForDisposition = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  signingSecrets,
  signingPrimaryKeyId,
  maxEvents = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const required = booleanValue(requiredForDisposition, 'requiredForDisposition');
  if (selectedMode === 'disabled') {
    if (required) throw new TypeError('Required time-attestation governance cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('A time-attestation governance directory is required.');

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const signing = parseSigningKeyring(signingSecrets, signingPrimaryKeyId);
  const eventLimit = integer(maxEvents, 'maxEvents', 100, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function record(tenantId, input, { actor } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const governedBy = identifier(actor, 'actor');
    const submitted = normaliseEventInput(input);
    const recordedAt = now().toISOString();
    const eventId = `NGE-${sha256(stableStringify({ tenantId: tenant, ...submitted })).slice(0, 32)}`;

    return lock.withLock(`evidence-time-attestation-governance:${tenant}`, () => {
      const index = loadIndex(tenant);
      const duplicate = index.events.find((event) => event.eventId === eventId);
      if (duplicate) return { recorded: false, duplicate: true, event: publicEvent(duplicate) };
      if (index.events.length >= eventLimit) {
        throw new EvidenceTimeAttestationGovernanceStoreError('The governance journal has reached its configured capacity.', {
          reason: 'event_capacity', maxEvents: eventLimit
        });
      }
      const event = {
        format: EVENT_FORMAT,
        version: 1,
        eventId,
        tenantId: tenant,
        ...submitted,
        sequence: index.sequence + 1,
        recordedAt,
        recordedBy: governedBy,
        previousHash: index.headHash
      };
      event.hash = eventHash(event);
      const signed = signEvent(event, signing);
      index.events.push(signed);
      index.sequence = signed.sequence;
      index.headHash = signed.hash;
      index.updatedAt = signed.recordedAt;
      saveIndex(tenant, index);
      return { recorded: true, duplicate: false, event: publicEvent(signed) };
    });
  }

  function list(tenantId, {
    eventType = null,
    attestationId = null,
    providerId = null,
    keyId = null,
    limit = 500
  } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const type = eventType === null ? null : enumValue(eventType, EVENT_TYPES, 'eventType');
    const attestation = attestationId === null ? null : attestationIdentifier(attestationId);
    const provider = providerId === null ? null : identifier(providerId, 'providerId');
    const key = keyId === null ? null : identifier(keyId, 'keyId');
    let events = loadSafe(tenant).events;
    if (type) events = events.filter((event) => event.eventType === type);
    if (attestation) events = events.filter((event) => event.attestationId === attestation || event.replacementAttestationId === attestation);
    if (provider) events = events.filter((event) => event.providerId === provider);
    if (key) events = events.filter((event) => event.keyId === key);
    return events.slice(-integer(limit, 'limit', 1, 5000)).reverse().map(publicEvent);
  }

  function evaluate(tenantId, attestations, { at = now().toISOString() } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    if (!Array.isArray(attestations)) throw new EvidenceValidationError('attestations must be an array.', { field: 'attestations' });
    const evaluationTime = isoDate(at, 'at');
    const index = loadSafe(tenant);
    const applicable = index.events.filter((event) => event.effectiveAt <= evaluationTime);
    const known = new Map(attestations.map((attestation) => [attestationIdentifier(attestation.attestationId), normaliseAttestation(attestation)]));
    const decisions = new Map();

    for (const attestation of known.values()) {
      const reasons = [];
      for (const event of applicable) {
        if (!eventApplies(event, attestation)) continue;
        reasons.push({
          eventId: event.eventId,
          eventType: event.eventType,
          effectiveAt: event.effectiveAt,
          reasonCode: event.reasonCode,
          replacementAttestationId: event.replacementAttestationId ?? null,
          retroactive: event.retroactive
        });
      }
      decisions.set(attestation.attestationId, {
        attestationId: attestation.attestationId,
        cryptographicallyValid: true,
        operationallyAcceptable: reasons.length === 0,
        status: reasons.length === 0 ? 'acceptable' : reasons.some((reason) => reason.eventType === 'attestation_superseded') ? 'superseded' : 'revoked',
        reasons
      });
    }
    return {
      valid: true,
      tenantId: tenant,
      evaluatedAt: evaluationTime,
      eventsConsidered: applicable.length,
      decisions
    };
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    return {
      valid: true,
      tenantId: tenant,
      checkedEvents: index.events.length,
      headSequence: index.sequence,
      headHash: index.headHash
    };
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const index = loadSafe(tenant);
      const counts = {
        attestationRevocations: 0,
        providerRevocations: 0,
        keyRevocations: 0,
        supersessions: 0
      };
      for (const event of index.events) {
        if (event.eventType === 'attestation_revoked') counts.attestationRevocations += 1;
        else if (event.eventType === 'provider_revoked') counts.providerRevocations += 1;
        else if (event.eventType === 'key_revoked') counts.keyRevocations += 1;
        else if (event.eventType === 'attestation_superseded') counts.supersessions += 1;
      }
      return {
        status: 'ready',
        enabled: true,
        requiredForDisposition: required,
        events: index.events.length,
        headSequence: index.sequence,
        headHash: index.headHash,
        ...counts
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        error: error?.code ?? 'evidence_time_attestation_governance_store_unavailable'
      };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(root, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && entry.name !== '.locks').length;
      return {
        status: 'ready',
        enabled: true,
        requiredForDisposition: required,
        mode: 'shared-file-encrypted-time-attestation-governance',
        encrypted: true,
        signedEvents: true,
        appendOnly: true,
        separatesCryptographicValidity: true,
        maximumEvents: eventLimit,
        tenantDirectoryCount,
        mutex: lock.health()
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        mode: 'shared-file-encrypted-time-attestation-governance',
        error: error?.code ?? 'evidence_time_attestation_governance_store_unavailable'
      };
    }
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) {
      if (error instanceof EvidenceTimeAttestationGovernanceStoreError
          || error instanceof EvidenceTimeAttestationGovernanceIntegrityError) throw error;
      throw new EvidenceTimeAttestationGovernanceStoreError('The governance journal could not be loaded.', {}, error);
    }
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant, now());
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceTimeAttestationGovernanceStoreError('The governance journal is unreadable.', {}, error); }
    const index = decryptEvidenceJson(
      envelope,
      encryption,
      indexAad(tenant),
      EvidenceTimeAttestationGovernanceIntegrityError
    );
    verifyIndex(index, tenant, signing);
    return index;
  }

  function saveIndex(tenant, index) {
    try {
      const envelope = encryptEvidenceJson(index, encryption, indexAad(tenant));
      atomicWriteEvidenceJson(indexPath(tenant), envelope);
    } catch (error) {
      if (error instanceof EvidenceTimeAttestationGovernanceStoreError
          || error instanceof EvidenceTimeAttestationGovernanceIntegrityError) throw error;
      throw new EvidenceTimeAttestationGovernanceStoreError('The governance journal could not be committed.', {}, error);
    }
  }

  function indexPath(tenant) {
    return resolve(tenantEvidenceDirectory(root, tenant), 'time-attestation-governance.enc.json');
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    requiredForDisposition: required,
    record,
    list,
    evaluate,
    verifyTenant,
    tenantStatus,
    health
  });
}

export function createEvidenceTimeAttestationGovernanceStoreFromEnvironment({ env = process.env } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE) ?? 'disabled';
  const requiredForDisposition = parseBoolean(
    environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_REQUIRED_FOR_DISPOSITION) ?? false
  );
  if (mode === 'disabled') return createEvidenceTimeAttestationGovernanceStore({ mode, requiredForDisposition });
  const rawKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_KEYS);
  const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_PRIMARY_KEY_ID);
  const rawSigning = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_SIGNING_SECRETS);
  const primarySigningKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_PRIMARY_SIGNING_KEY_ID);
  if (!rawKeys) throw configurationError('Dedicated governance encryption keys are required.', 'missing_governance_encryption_keys');
  if (!primaryKeyId) throw configurationError('A governance primary encryption key ID is required.', 'missing_governance_primary_key_id');
  if (!rawSigning) throw configurationError('Dedicated governance signing secrets are required.', 'missing_governance_signing_secrets');
  if (!primarySigningKeyId) throw configurationError('A governance primary signing key ID is required.', 'missing_governance_primary_signing_key_id');
  try {
    return createEvidenceTimeAttestationGovernanceStore({
      mode,
      requiredForDisposition,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_DIR),
      encryptionKeys: JSON.parse(rawKeys),
      encryptionPrimaryKeyId: primaryKeyId,
      signingSecrets: JSON.parse(rawSigning),
      signingPrimaryKeyId: primarySigningKeyId,
      maxEvents: Number(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MAX_EVENTS) ?? 100_000)
    });
  } catch (error) {
    if (error instanceof EvidenceTimeAttestationGovernanceStoreError) throw error;
    throw new EvidenceTimeAttestationGovernanceStoreError('Time-attestation governance configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

function normaliseEventInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('A valid time-attestation governance event is required.');
  }
  const eventType = enumValue(input.eventType, EVENT_TYPES, 'eventType');
  const effectiveAt = isoDate(input.effectiveAt, 'effectiveAt');
  const reasonCode = enumValue(input.reasonCode, REASON_CODES, 'reasonCode');
  const reason = cleanText(input.reason, 'reason', 10, 500);
  const retroactive = input.retroactive === undefined ? false : booleanValue(input.retroactive, 'retroactive');
  const result = {
    eventType,
    effectiveAt,
    reasonCode,
    reason,
    retroactive,
    archiveId: null,
    attestationId: null,
    providerId: null,
    keyId: null,
    replacementAttestationId: null
  };
  if (eventType === 'attestation_revoked') {
    result.archiveId = archiveIdentifier(input.archiveId);
    result.attestationId = attestationIdentifier(input.attestationId);
  } else if (eventType === 'attestation_superseded') {
    result.archiveId = archiveIdentifier(input.archiveId);
    result.attestationId = attestationIdentifier(input.attestationId);
    result.replacementAttestationId = attestationIdentifier(input.replacementAttestationId);
    if (result.attestationId === result.replacementAttestationId) {
      throw new EvidenceValidationError('A superseding attestation must be different from the original.', {
        field: 'replacementAttestationId'
      });
    }
  } else if (eventType === 'provider_revoked') {
    result.providerId = identifier(input.providerId, 'providerId');
  } else if (eventType === 'key_revoked') {
    result.providerId = identifier(input.providerId, 'providerId');
    result.keyId = identifier(input.keyId, 'keyId');
  }
  return result;
}

function normaliseAttestation(attestation) {
  if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
    throw new EvidenceValidationError('A valid time attestation is required.');
  }
  return {
    attestationId: attestationIdentifier(attestation.attestationId),
    archiveId: archiveIdentifier(attestation.archiveId),
    providerId: identifier(attestation.providerId, 'providerId'),
    keyId: identifier(attestation.keyId, 'keyId'),
    timestamp: isoDate(attestation.timestamp, 'timestamp')
  };
}

function eventApplies(event, attestation) {
  if (event.eventType === 'attestation_revoked') return event.attestationId === attestation.attestationId;
  if (event.eventType === 'attestation_superseded') return event.attestationId === attestation.attestationId;
  if (event.eventType === 'provider_revoked' && event.providerId === attestation.providerId) {
    return event.retroactive || attestation.timestamp >= event.effectiveAt;
  }
  if (event.eventType === 'key_revoked'
      && event.providerId === attestation.providerId && event.keyId === attestation.keyId) {
    return event.retroactive || attestation.timestamp >= event.effectiveAt;
  }
  return false;
}

function verifyIndex(index, tenant, signing) {
  if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant
      || !Array.isArray(index.events) || !Number.isInteger(index.sequence) || index.sequence < 0) {
    throw new EvidenceTimeAttestationGovernanceIntegrityError('The governance journal has an invalid identity.');
  }
  let previousHash = null;
  let sequence = 0;
  for (const event of index.events) {
    sequence += 1;
    if (!event || event.format !== EVENT_FORMAT || event.version !== 1 || event.tenantId !== tenant
        || event.sequence !== sequence || event.previousHash !== previousHash) {
      throw new EvidenceTimeAttestationGovernanceIntegrityError('The governance event chain is invalid.', {
        sequence
      });
    }
    verifyEventSignature(event, signing);
    if (event.hash !== eventHash(event)) {
      throw new EvidenceTimeAttestationGovernanceIntegrityError('A governance event hash is invalid.', {
        eventId: event.eventId
      });
    }
    previousHash = event.hash;
  }
  if (index.sequence !== sequence || index.headHash !== previousHash) {
    throw new EvidenceTimeAttestationGovernanceIntegrityError('The governance journal head is invalid.');
  }
}

function emptyIndex(tenantId, now) {
  const timestamp = now.toISOString();
  return {
    format: INDEX_FORMAT,
    version: 1,
    tenantId,
    sequence: 0,
    headHash: null,
    createdAt: timestamp,
    updatedAt: timestamp,
    events: []
  };
}

function signEvent(event, signing) {
  const signingKeyId = signing.primaryKeyId;
  const signature = createHmac('sha256', signing.keys.get(signingKeyId))
    .update(eventSignaturePayload(event))
    .digest('base64');
  return { ...event, signingKeyId, signature };
}

function verifyEventSignature(event, signing) {
  const key = signing.keys.get(event.signingKeyId);
  if (!key) {
    throw new EvidenceTimeAttestationGovernanceIntegrityError('A governance event references an unavailable signing key.', {
      signingKeyId: event.signingKeyId
    });
  }
  const expected = createHmac('sha256', key).update(eventSignaturePayload(event)).digest();
  let supplied;
  try { supplied = strictBase64(event.signature, 'governance event signature'); }
  catch (error) {
    throw new EvidenceTimeAttestationGovernanceIntegrityError('A governance event signature is invalid.', {
      eventId: event.eventId
    }, error);
  }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new EvidenceTimeAttestationGovernanceIntegrityError('A governance event signature verification failed.', {
      eventId: event.eventId
    });
  }
}

function eventHash(event) {
  const { signingKeyId, signature, hash, ...body } = event;
  void signingKeyId;
  void signature;
  void hash;
  return sha256(stableStringify(body));
}

function eventSignaturePayload(event) {
  const { signingKeyId, signature, ...body } = event;
  void signingKeyId;
  void signature;
  return stableStringify(body);
}

function publicEvent(event) {
  return {
    eventId: event.eventId,
    eventType: event.eventType,
    archiveId: event.archiveId,
    attestationId: event.attestationId,
    providerId: event.providerId,
    keyId: event.keyId,
    replacementAttestationId: event.replacementAttestationId,
    effectiveAt: event.effectiveAt,
    retroactive: event.retroactive,
    reasonCode: event.reasonCode,
    reason: event.reason,
    recordedAt: event.recordedAt,
    recordedBy: event.recordedBy,
    sequence: event.sequence,
    previousHash: event.previousHash,
    hash: event.hash,
    signingKeyId: event.signingKeyId,
    signature: event.signature
  };
}

function parseSigningKeyring(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('Time-attestation governance signing secrets must be an object.');
  }
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 100) {
    throw new TypeError('Time-attestation governance signing secrets must contain 1 to 100 entries.');
  }
  const keys = new Map(entries.map(([keyId, encoded]) => {
    identifier(keyId, 'signingKeyId');
    const secret = strictBase64(encoded, `governance signing secret ${keyId}`);
    if (secret.length < 32 || secret.length > 128) {
      throw new TypeError(`Governance signing secret ${keyId} must decode to 32 to 128 bytes.`);
    }
    return [keyId, secret];
  }));
  const primary = String(primaryKeyId ?? entries[0][0]);
  if (!keys.has(primary)) throw new TypeError('The governance primary signing key ID is not present in the keyring.');
  return Object.freeze({ keys, primaryKeyId: primary });
}

function disabledStore() {
  const status = Object.freeze({
    status: 'disabled', enabled: false, requiredForDisposition: false, mode: 'disabled'
  });
  return Object.freeze({
    mode: 'disabled', enabled: false, requiredForDisposition: false,
    record() { throw new EvidenceConflictError('Time-attestation governance is disabled.'); },
    list() { return []; },
    evaluate(tenantId, attestations, { at = new Date().toISOString() } = {}) {
      return {
        valid: true,
        tenantId,
        evaluatedAt: at,
        eventsConsidered: 0,
        decisions: new Map((attestations ?? []).map((attestation) => [
          attestation.attestationId,
          {
            attestationId: attestation.attestationId,
            cryptographicallyValid: true,
            operationallyAcceptable: true,
            status: 'acceptable',
            reasons: []
          }
        ]))
      };
    },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedEvents: 0, headSequence: 0, headHash: null }; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}

function configurationError(message, reason) {
  return new EvidenceTimeAttestationGovernanceStoreError(message, { reason });
}
function indexAad(tenantId) { return `basitclaw:evidence-time-attestation-governance:index:${tenantId}`; }
function attestationIdentifier(value) { const id = String(value ?? ''); if (!ATTESTATION_ID.test(id)) throw new EvidenceValidationError('attestationId is invalid.', { field: 'attestationId' }); return id; }
function archiveIdentifier(value) { const id = String(value ?? ''); if (!ARCHIVE_ID.test(id)) throw new EvidenceValidationError('archiveId is invalid.', { field: 'archiveId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new EvidenceValidationError(`${field} must be true or false.`, { field }); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
