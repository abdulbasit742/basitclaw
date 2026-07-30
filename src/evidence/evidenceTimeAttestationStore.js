import {
  constants,
  createPublicKey,
  verify as verifyAsymmetric
} from 'node:crypto';
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

const INDEX_FORMAT = 'basitclaw-evidence-time-attestation-index';
const RECORD_FORMAT = 'basitclaw-evidence-time-attestation';
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);
const ALGORITHMS = new Set(['ed25519', 'rsa-pss-sha256']);
const ALLOWED_FIELDS = new Set([
  'tenantId', 'archiveId', 'providerId', 'keyId', 'receiptSha256', 'objectEnvelopeSha256',
  'timestamp', 'policyId', 'nonce', 'signature'
]);

export class EvidenceTimeAttestationStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence time-attestation store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceTimeAttestationStoreError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_STORE_UNAVAILABLE';
  }
}

export class EvidenceTimeAttestationIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence time-attestation integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceTimeAttestationIntegrityError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_INTEGRITY_FAILED';
  }
}

export class EvidenceTimeAttestationAuthenticationError extends Error {
  constructor(message = 'The time-authority signature is invalid.', details = {}) {
    super(message);
    this.name = 'EvidenceTimeAttestationAuthenticationError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_AUTHENTICATION_FAILED';
    this.statusCode = 401;
    this.details = details;
  }
}

export class EvidenceTimeAttestationRequiredError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('Independent time-attestation quorum is required before evidence disposition.', { evidenceId, ...details });
    this.name = 'EvidenceTimeAttestationRequiredError';
    this.code = 'EVIDENCE_TIME_ATTESTATION_REQUIRED';
  }
}

export function createEvidenceTimeAttestationStore({
  mode = 'disabled',
  requiredForDisposition = false,
  minimumProviders = 1,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  providers,
  clockSkewSeconds = 300,
  maximumDelayMinutes = 1440,
  maxRecords = 100_000,
  resolveChallenge,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const required = booleanValue(requiredForDisposition, 'requiredForDisposition');
  const quorum = integer(minimumProviders, 'minimumProviders', 1, 10);
  if (selectedMode === 'disabled') {
    if (required) throw new TypeError('Required time attestations cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('A time-attestation directory is required.');
  if (typeof resolveChallenge !== 'function') throw new TypeError('A preservation challenge resolver is required.');

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const authorities = parseProviders(providers);
  if (quorum > authorities.size) throw new TypeError('minimumProviders cannot exceed configured time authorities.');
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 0, 3600) * 1000;
  const maximumDelayMs = integer(maximumDelayMinutes, 'maximumDelayMinutes', 1, 43_200) * 60_000;
  const recordLimit = integer(maxRecords, 'maxRecords', 100, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function challenge(tenantId, archiveId) {
    return normaliseChallenge(resolveChallenge(identifier(tenantId, 'tenantId'), archiveIdentifier(archiveId)));
  }

  function record(input) {
    const submitted = normaliseSubmission(input);
    const authority = authorityFor(submitted.providerId, submitted.keyId);
    const canonical = canonicalAttestation(submitted);
    verifyAuthoritySignature(authority, canonical, submitted.signature, submitted.providerId, submitted.keyId);
    const attestationId = `NTA-${sha256(`${canonical}\n${submitted.signature}`).slice(0, 32)}`;

    // Resolve tenant/archive state only after the authority has authenticated.
    const currentChallenge = challenge(submitted.tenantId, submitted.archiveId);
    assertChallengeMatch(submitted, currentChallenge);
    assertTimestamp(submitted.timestamp, currentChallenge.archivedAt);

    return lock.withLock(`evidence-time-attestations:${submitted.tenantId}`, () => {
      const index = loadIndex(submitted.tenantId);
      const duplicate = index.records.find((entry) => entry.attestationId === attestationId);
      if (duplicate) return { accepted: false, duplicate: true, attestation: publicRecord(duplicate) };
      if (index.records.some((entry) => entry.providerId === submitted.providerId
          && entry.keyId === submitted.keyId && entry.nonce === submitted.nonce)) {
        throw new EvidenceTimeAttestationAuthenticationError('The time-authority nonce has already been used.', {
          reason: 'nonce_replay', providerId: submitted.providerId, keyId: submitted.keyId
        });
      }
      if (index.records.length >= recordLimit) {
        throw new EvidenceTimeAttestationStoreError('The time-attestation store has reached its configured capacity.', {
          reason: 'record_capacity', maxRecords: recordLimit
        });
      }
      const entry = {
        format: RECORD_FORMAT,
        version: 1,
        attestationId,
        ...submitted,
        sequence: index.sequence + 1,
        receivedAt: now().toISOString(),
        previousHash: index.headHash
      };
      entry.hash = recordHash(entry);
      index.records.push(entry);
      index.sequence = entry.sequence;
      index.headHash = entry.hash;
      index.updatedAt = entry.receivedAt;
      saveIndex(submitted.tenantId, index);
      return { accepted: true, duplicate: false, attestation: publicRecord(entry) };
    });
  }

  function list(tenantId, { archiveId = null, providerId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const archive = archiveId === null ? null : archiveIdentifier(archiveId);
    const provider = providerId === null ? null : identifier(providerId, 'providerId');
    let records = loadSafe(tenant).records;
    if (archive) records = records.filter((entry) => entry.archiveId === archive);
    if (provider) records = records.filter((entry) => entry.providerId === provider);
    return records
      .slice(-integer(limit, 'limit', 1, 5000))
      .reverse()
      .map(publicRecord);
  }

  function verifyArchives(tenantId, archiveIds = null) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant); // loadIndex already validates the full hash chain once.
    const requested = archiveIds === null
      ? [...new Set(index.records.map((entry) => entry.archiveId))]
      : [...new Set(archiveIds.map(archiveIdentifier))];
    return verifyArchivesWithIndex(tenant, index, requested);
  }

  function verifyArchive(tenantId, archiveId) {
    const archive = archiveIdentifier(archiveId);
    const batch = verifyArchives(tenantId, [archive]);
    return batch.results.get(archive);
  }

  function quorumForArchives(tenantId, archiveIds) {
    const batch = verifyArchives(tenantId, archiveIds);
    return new Map([...batch.results].map(([archiveId, verification]) => [
      archiveId,
      verification.quorumSatisfied ? verification : null
    ]));
  }

  function quorumForArchive(tenantId, archiveId) {
    return quorumForArchives(tenantId, [archiveId]).get(archiveIdentifier(archiveId)) ?? null;
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const batch = verifyArchives(tenant, null);
    return {
      valid: true,
      tenantId: tenant,
      checkedAttestations: batch.checkedAttestations,
      checkedArchives: batch.results.size,
      headSequence: batch.headSequence,
      headHash: batch.headHash
    };
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const index = loadSafe(tenant);
      const archiveProviders = new Map();
      for (const entry of index.records) {
        const providersForArchive = archiveProviders.get(entry.archiveId) ?? new Set();
        providersForArchive.add(entry.providerId);
        archiveProviders.set(entry.archiveId, providersForArchive);
      }
      const quorumArchives = [...archiveProviders.values()].filter((set) => set.size >= quorum).length;
      return {
        status: 'ready',
        enabled: true,
        requiredForDisposition: required,
        minimumProviders: quorum,
        attestations: index.records.length,
        archives: archiveProviders.size,
        quorumArchives,
        headSequence: index.sequence,
        headHash: index.headHash
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        minimumProviders: quorum,
        error: error?.code ?? 'evidence_time_attestation_store_unavailable'
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
        mode: 'shared-file-encrypted-time-attestations',
        encrypted: true,
        asymmetricSignatures: true,
        replayProtected: true,
        batchedVerification: true,
        minimumProviders: quorum,
        configuredProviders: authorities.size,
        clockSkewSeconds: skewMs / 1000,
        maximumDelayMinutes: maximumDelayMs / 60_000,
        maxRecords: recordLimit,
        tenantDirectoryCount,
        mutex: lock.health()
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, requiredForDisposition: required,
        mode: 'shared-file-encrypted-time-attestations',
        error: error?.code ?? 'evidence_time_attestation_store_unavailable'
      };
    }
  }

  function verifyArchivesWithIndex(tenant, index, archiveIds) {
    const grouped = new Map(archiveIds.map((archiveId) => [archiveId, []]));
    for (const entry of index.records) {
      if (grouped.has(entry.archiveId)) grouped.get(entry.archiveId).push(entry);
    }
    const results = new Map();
    let checkedAttestations = 0;
    for (const archiveId of archiveIds) {
      const expected = challenge(tenant, archiveId);
      const providers = new Set();
      const records = grouped.get(archiveId) ?? [];
      for (const entry of records) {
        verifyStoredRecord(entry, expected);
        providers.add(entry.providerId);
        checkedAttestations += 1;
      }
      results.set(archiveId, {
        valid: true,
        tenantId: tenant,
        archiveId,
        attestationCount: records.length,
        distinctProviders: providers.size,
        minimumProviders: quorum,
        quorumSatisfied: providers.size >= quorum,
        providerIds: [...providers].sort()
      });
    }
    return {
      valid: true,
      tenantId: tenant,
      results,
      checkedAttestations,
      headSequence: index.sequence,
      headHash: index.headHash
    };
  }

  function verifyStoredRecord(entry, expected) {
    assertChallengeMatch(entry, expected);
    assertTimestamp(entry.timestamp, expected.archivedAt);
    const authority = authorityFor(entry.providerId, entry.keyId);
    try {
      verifyAuthoritySignature(authority, canonicalAttestation(entry), entry.signature, entry.providerId, entry.keyId);
    } catch (error) {
      if (error instanceof EvidenceTimeAttestationAuthenticationError) {
        throw new EvidenceTimeAttestationIntegrityError('A stored time-attestation signature is invalid.', {
          attestationId: entry.attestationId,
          providerId: entry.providerId,
          keyId: entry.keyId
        }, error);
      }
      throw error;
    }
    if (entry.hash !== recordHash(entry)) {
      throw new EvidenceTimeAttestationIntegrityError('A time-attestation record hash is invalid.', {
        attestationId: entry.attestationId
      });
    }
  }

  function authorityFor(providerId, keyId) {
    const provider = authorities.get(identifier(providerId, 'providerId'));
    const authority = provider?.get(identifier(keyId, 'keyId'));
    if (!authority) {
      throw new EvidenceTimeAttestationAuthenticationError('The time-authority provider or key is not configured.', {
        reason: 'unknown_authority_key', providerId, keyId
      });
    }
    return authority;
  }

  function assertTimestamp(timestamp, archivedAt) {
    const time = new Date(timestamp).getTime();
    const archived = new Date(archivedAt).getTime();
    const current = now().getTime();
    if (!Number.isFinite(time) || !Number.isFinite(archived)) {
      throw new EvidenceValidationError('The time-attestation timestamp is invalid.', { field: 'timestamp' });
    }
    if (time < archived - skewMs) {
      throw new EvidenceTimeAttestationAuthenticationError('The authority timestamp predates the preservation receipt.', {
        reason: 'timestamp_before_archive'
      });
    }
    if (time > current + skewMs) {
      throw new EvidenceTimeAttestationAuthenticationError('The authority timestamp is too far in the future.', {
        reason: 'timestamp_future'
      });
    }
    if (time - archived > maximumDelayMs) {
      throw new EvidenceTimeAttestationAuthenticationError('The authority timestamp exceeds the configured issuance delay.', {
        reason: 'timestamp_delay_exceeded'
      });
    }
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) {
      if (error instanceof EvidenceTimeAttestationStoreError || error instanceof EvidenceTimeAttestationIntegrityError) throw error;
      throw new EvidenceTimeAttestationStoreError('The time-attestation index could not be loaded.', {}, error);
    }
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant, now());
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceTimeAttestationStoreError('The time-attestation index is unreadable.', {}, error); }
    const index = decryptEvidenceJson(envelope, encryption, indexAad(tenant), EvidenceTimeAttestationIntegrityError);
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.records)) {
      throw new EvidenceTimeAttestationIntegrityError('The time-attestation index identity is invalid.');
    }
    verifyChain(index);
    return index;
  }

  function saveIndex(tenant, index) {
    atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, encryption, indexAad(tenant)));
  }

  function indexPath(tenant) {
    return resolve(tenantEvidenceDirectory(root, tenant), 'time-attestations.evidence');
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    requiredForDisposition: required,
    minimumProviders: quorum,
    directory: root,
    challenge,
    record,
    list,
    verifyArchive,
    verifyArchives,
    quorumForArchive,
    quorumForArchives,
    verifyTenant,
    tenantStatus,
    health
  });
}

export function createEvidenceTimeAttestationStoreFromEnvironment({ env = process.env, resolveChallenge } = {}) {
  try {
    const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_MODE) ?? 'disabled';
    const requiredForDisposition = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUIRED_FOR_DISPOSITION) ?? false);
    if (mode === 'disabled') {
      if (requiredForDisposition) {
        throw new EvidenceTimeAttestationStoreError('Required time attestations cannot be disabled.', {
          reason: 'invalid_notary_configuration'
        });
      }
      return createEvidenceTimeAttestationStore({ mode, requiredForDisposition });
    }
    const rawKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEYS);
    const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_PRIMARY_KEY_ID);
    const rawProviders = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS);
    if (!rawKeys || !primaryKeyId || !rawProviders) {
      throw new EvidenceTimeAttestationStoreError('Time-attestation keys, primary key ID and providers are required.', {
        reason: 'missing_notary_configuration'
      });
    }
    return createEvidenceTimeAttestationStore({
      mode,
      requiredForDisposition,
      minimumProviders: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_MINIMUM_PROVIDERS) ?? 1,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_DIR)
        ?? '.runtime-data/workforce-audit-evidence-notary',
      encryptionKeys: JSON.parse(rawKeys),
      encryptionPrimaryKeyId: primaryKeyId,
      providers: JSON.parse(rawProviders),
      clockSkewSeconds: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_CLOCK_SKEW_SECONDS) ?? 300,
      maximumDelayMinutes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_MAX_DELAY_MINUTES) ?? 1440,
      maxRecords: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_MAX_RECORDS) ?? 100_000,
      resolveChallenge
    });
  } catch (error) {
    if (error instanceof EvidenceTimeAttestationStoreError) throw error;
    throw new EvidenceTimeAttestationStoreError('Time-attestation configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

export function canonicalTimeAttestation(input) {
  return [
    'basitclaw-evidence-time-attestation-v1',
    input.providerId,
    input.keyId,
    input.tenantId,
    input.archiveId,
    input.receiptSha256,
    input.objectEnvelopeSha256,
    input.timestamp,
    input.policyId,
    input.nonce
  ].join('\n');
}

function normaliseSubmission(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('A valid time-attestation submission is required.');
  }
  for (const field of Object.keys(input)) {
    if (!ALLOWED_FIELDS.has(field)) throw new EvidenceValidationError(`Unsupported time-attestation field ${field}.`, { field });
  }
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    archiveId: archiveIdentifier(input.archiveId),
    providerId: identifier(input.providerId, 'providerId'),
    keyId: identifier(input.keyId, 'keyId'),
    receiptSha256: hashValue(input.receiptSha256, 'receiptSha256'),
    objectEnvelopeSha256: hashValue(input.objectEnvelopeSha256, 'objectEnvelopeSha256'),
    timestamp: isoDate(input.timestamp, 'timestamp'),
    policyId: identifier(input.policyId, 'policyId'),
    nonce: identifier(input.nonce, 'nonce'),
    signature: canonicalBase64(input.signature, 'signature')
  };
}

function normaliseChallenge(input) {
  if (!input || typeof input !== 'object') throw new EvidenceTimeAttestationStoreError('The preservation challenge is unavailable.');
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    archiveId: archiveIdentifier(input.archiveId),
    receiptSha256: hashValue(input.receiptSha256, 'receiptSha256'),
    objectEnvelopeSha256: hashValue(input.objectEnvelopeSha256, 'objectEnvelopeSha256'),
    archivedAt: isoDate(input.archivedAt, 'archivedAt'),
    retentionUntil: isoDate(input.retentionUntil, 'retentionUntil')
  };
}

function assertChallengeMatch(input, expected) {
  if (input.tenantId !== expected.tenantId || input.archiveId !== expected.archiveId
      || input.receiptSha256 !== expected.receiptSha256
      || input.objectEnvelopeSha256 !== expected.objectEnvelopeSha256) {
    throw new EvidenceTimeAttestationAuthenticationError('The time attestation does not match the preservation challenge.', {
      reason: 'challenge_mismatch', archiveId: input.archiveId
    });
  }
}

function parseProviders(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Time-attestation providers must be an object.');
  const providers = new Map();
  for (const [providerId, provider] of Object.entries(raw)) {
    identifier(providerId, 'providerId');
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`Provider ${providerId} must be an object.`);
    const rawKeys = provider.keys;
    if (!rawKeys || typeof rawKeys !== 'object' || Array.isArray(rawKeys) || !Object.keys(rawKeys).length) {
      throw new TypeError(`Provider ${providerId} must contain keys.`);
    }
    const keys = new Map();
    for (const [keyId, config] of Object.entries(rawKeys)) {
      identifier(keyId, 'keyId');
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Provider key ${providerId}/${keyId} must be an object.`);
      const algorithm = enumValue(config.algorithm, ALGORITHMS, 'algorithm');
      const publicKey = createPublicKey(String(config.publicKeyPem ?? ''));
      if (algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') {
        throw new TypeError(`Provider key ${providerId}/${keyId} must be Ed25519.`);
      }
      if (algorithm === 'rsa-pss-sha256') {
        if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) throw new TypeError(`Provider key ${providerId}/${keyId} must be RSA.`);
        if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Provider key ${providerId}/${keyId} must be at least 2048 bits.`);
      }
      keys.set(keyId, Object.freeze({ algorithm, publicKey }));
    }
    providers.set(providerId, keys);
  }
  if (!providers.size || providers.size > 20) throw new TypeError('Time-attestation providers must contain 1 to 20 providers.');
  return providers;
}

function verifyAuthoritySignature(authority, canonical, encodedSignature, providerId, keyId) {
  let signature;
  try { signature = strictBase64(encodedSignature, 'authority signature'); }
  catch (error) {
    throw new EvidenceTimeAttestationAuthenticationError('The authority signature is malformed.', {
      reason: 'signature_encoding', providerId, keyId
    });
  }
  const data = Buffer.from(canonical, 'utf8');
  let valid = false;
  try {
    valid = authority.algorithm === 'ed25519'
      ? verifyAsymmetric(null, data, authority.publicKey, signature)
      : verifyAsymmetric('sha256', data, {
        key: authority.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO
      }, signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new EvidenceTimeAttestationAuthenticationError(undefined, {
      reason: 'signature_invalid', providerId, keyId
    });
  }
}

function canonicalAttestation(input) { return canonicalTimeAttestation(input); }
function recordHash(entry) {
  const { hash, ...body } = entry;
  return sha256(stableStringify(body));
}
function verifyChain(index) {
  let previousHash = null;
  let expectedSequence = 1;
  for (const entry of index.records) {
    if (entry.sequence !== expectedSequence || entry.previousHash !== previousHash || entry.hash !== recordHash(entry)) {
      throw new EvidenceTimeAttestationIntegrityError('The time-attestation hash chain is invalid.', {
        attestationId: entry.attestationId, expectedSequence
      });
    }
    previousHash = entry.hash;
    expectedSequence += 1;
  }
  if (index.sequence !== expectedSequence - 1 || index.headHash !== previousHash) {
    throw new EvidenceTimeAttestationIntegrityError('The time-attestation chain head is inconsistent.');
  }
}
function emptyIndex(tenantId, date) {
  const time = date.toISOString();
  return { format: INDEX_FORMAT, version: 1, tenantId, createdAt: time, updatedAt: time, sequence: 0, headHash: null, records: [] };
}
function publicRecord(entry) {
  return {
    attestationId: entry.attestationId,
    archiveId: entry.archiveId,
    providerId: entry.providerId,
    keyId: entry.keyId,
    receiptSha256: entry.receiptSha256,
    objectEnvelopeSha256: entry.objectEnvelopeSha256,
    timestamp: entry.timestamp,
    policyId: entry.policyId,
    nonce: entry.nonce,
    sequence: entry.sequence,
    receivedAt: entry.receivedAt,
    hash: entry.hash,
    previousHash: entry.previousHash
  };
}
function indexAad(tenantId) { return `basitclaw:evidence-time-attestations:${tenantId}`; }
function archiveIdentifier(value) { const id = String(value ?? ''); if (!ARCHIVE_ID.test(id)) throw new EvidenceValidationError('archiveId is invalid.', { field: 'archiveId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function canonicalBase64(value, field) { const buffer = strictBase64(value, field); return buffer.toString('base64'); }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be true or false.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return parsed; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, requiredForDisposition: false, mode: 'disabled', minimumProviders: 0 });
  return Object.freeze({
    mode: 'disabled', enabled: false, requiredForDisposition: false, minimumProviders: 0,
    challenge() { throw new EvidenceConflictError('Evidence time attestations are disabled.'); },
    record() { throw new EvidenceConflictError('Evidence time attestations are disabled.'); },
    list() { return []; },
    verifyArchive() { throw new EvidenceConflictError('Evidence time attestations are disabled.'); },
    verifyArchives(tenantId) { return { valid: true, tenantId, results: new Map(), checkedAttestations: 0, headSequence: 0, headHash: null }; },
    quorumForArchive() { return null; },
    quorumForArchives(_tenantId, archiveIds = []) { return new Map(archiveIds.map((archiveId) => [archiveId, null])); },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedAttestations: 0, checkedArchives: 0 }; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}
