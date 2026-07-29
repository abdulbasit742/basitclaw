import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
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

const FORMAT = 'basitclaw-workforce-audit-external-scan-attestations';
const MODES = new Set(['disabled', 'observe', 'enforce']);
const VERDICTS = new Set(['clean', 'suspicious', 'malicious', 'error']);
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const ATTESTATION_ID = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}$/;
const NONCE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{15,127}$/;
const ATTESTATION_FIELDS = new Set([
  'attestationId', 'tenantId', 'evidenceId', 'version', 'contentSha256', 'verdict',
  'scannedAt', 'engine', 'engineVersion', 'definitionsVersion', 'findings'
]);

export class ExternalScanAuthenticationError extends Error {
  constructor(message = 'External scanner authentication failed.', details = {}) {
    super(message);
    this.name = 'ExternalScanAuthenticationError';
    this.code = 'EXTERNAL_SCAN_AUTHENTICATION_FAILED';
    this.statusCode = 401;
    this.details = details;
  }
}

export class ExternalScanStoreError extends EvidenceStoreError {
  constructor(message = 'The external scanner attestation registry is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'ExternalScanStoreError';
    this.code = 'EXTERNAL_SCAN_STORE_UNAVAILABLE';
  }
}

export class ExternalScanRequiredError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('A recent clean external scan attestation is required before quarantine release.', { evidenceId, ...details });
    this.name = 'ExternalScanRequiredError';
    this.code = 'EVIDENCE_EXTERNAL_SCAN_REQUIRED';
    this.statusCode = 423;
  }
}

export function createExternalScanAttestationRegistry({
  directory,
  keys,
  primaryKeyId,
  providers = {},
  mode = 'disabled',
  requiredForRelease = false,
  maxAttestationAgeMinutes = 1440,
  clockSkewSeconds = 300,
  eventRetention = 10_000,
  maxRecords = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const required = booleanValue(requiredForRelease, 'requiredForRelease');
  if (selectedMode === 'disabled') {
    if (required) throw new TypeError('Required external scanner attestations cannot be disabled.');
    return disabledRegistry();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence directory is required for external scanner attestations.');
  const keyring = parseEvidenceKeyring(keys, primaryKeyId);
  const providerKeys = parseProviders(providers);
  if (!providerKeys.size) throw new TypeError('At least one external scanner provider key is required.');
  const root = resolve(String(directory), '.external-scans');
  const safeMaxAgeMinutes = integer(maxAttestationAgeMinutes, 'maxAttestationAgeMinutes', 1, 525_600);
  const safeSkewSeconds = integer(clockSkewSeconds, 'clockSkewSeconds', 1, 3600);
  const retainedEvents = integer(eventRetention, 'eventRetention', 100, 100_000);
  const safeMaxRecords = integer(maxRecords, 'maxRecords', 100, 1_000_000);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });

  function acceptSigned(bodyBuffer, headers, validateTarget) {
    if (!Buffer.isBuffer(bodyBuffer)) throw new TypeError('External scan body must be a Buffer.');
    if (bodyBuffer.length < 2 || bodyBuffer.length > 262_144) throw new EvidenceValidationError('External scan attestation body must contain 2 to 262144 bytes.', { field: 'body' });
    const authentication = authenticate(bodyBuffer, headers);
    let input;
    try { input = JSON.parse(bodyBuffer.toString('utf8')); }
    catch { throw new EvidenceValidationError('External scan attestation body must be valid JSON.', { field: 'body' }); }
    const attestation = normaliseAttestation(input, authentication, now);
    const target = validateTarget(attestation);
    if (!target || target.contentSha256 !== attestation.contentSha256 || target.version !== attestation.version) {
      throw new EvidenceConflictError('External scan attestation does not match the immutable evidence version.', {
        evidenceId: attestation.evidenceId,
        version: attestation.version
      });
    }
    return record(attestation);
  }

  function authenticate(bodyBuffer, headers = {}) {
    const providerId = header(headers, 'x-basitclaw-scan-provider');
    const keyId = header(headers, 'x-basitclaw-scan-key-id');
    const timestamp = header(headers, 'x-basitclaw-scan-timestamp');
    const nonce = header(headers, 'x-basitclaw-scan-nonce');
    const signature = header(headers, 'x-basitclaw-scan-signature').toLowerCase();
    const provider = providerKeys.get(providerId);
    const secret = provider?.get(keyId);
    if (!provider || !secret || !NONCE.test(nonce) || !HASH.test(signature)) throw new ExternalScanAuthenticationError();
    const signedAt = validDate(timestamp, 'timestamp');
    const distanceSeconds = Math.abs(now().getTime() - signedAt.getTime()) / 1000;
    if (distanceSeconds > safeSkewSeconds) throw new ExternalScanAuthenticationError('External scanner timestamp is outside the allowed clock-skew window.', { reason: 'timestamp_out_of_window' });
    const canonical = `${providerId}\n${keyId}\n${signedAt.toISOString()}\n${nonce}\n${sha256(bodyBuffer)}`;
    const expected = createHmac('sha256', secret).update(canonical).digest();
    const supplied = Buffer.from(signature, 'hex');
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new ExternalScanAuthenticationError();
    return { providerId, keyId, signedAt: signedAt.toISOString(), nonce };
  }

  function record(attestation) {
    const tenant = identifier(attestation.tenantId, 'tenantId');
    return lock.withLock(`external-scan:${tenant}`, () => {
      const index = loadIndex(tenant);
      const existing = index.attestations.find((entry) => entry.attestationId === attestation.attestationId);
      const payloadHash = attestationPayloadHash(attestation);
      if (existing) {
        if (existing.payloadHash !== payloadHash) throw new EvidenceConflictError('External scan attestation ID already exists with different content.', { attestationId: attestation.attestationId });
        return { accepted: false, duplicate: true, attestation: publicAttestation(existing) };
      }
      if (index.attestations.length >= safeMaxRecords) throw new ExternalScanStoreError('External scan attestation capacity has been reached.', { maxRecords: safeMaxRecords });
      const stored = {
        ...attestation,
        receiptId: `ESC-${randomUUID().replaceAll('-', '')}`,
        receivedAt: now().toISOString(),
        sequence: index.sequence + 1,
        previousHash: index.headHash,
        payloadHash
      };
      stored.hash = recordHash(stored);
      index.attestations.push(stored);
      index.sequence = stored.sequence;
      index.headHash = stored.hash;
      if (!index.createdAt) index.createdAt = stored.receivedAt;
      index.updatedAt = stored.receivedAt;
      index.events.push({
        eventId: `ESE-${randomUUID().replaceAll('-', '')}`,
        sequence: index.eventSequence + 1,
        occurredAt: stored.receivedAt,
        action: 'external_scan.attestation_accepted',
        evidenceId: stored.evidenceId,
        metadata: { attestationId: stored.attestationId, providerId: stored.providerId, version: stored.version, verdict: stored.verdict }
      });
      index.eventSequence += 1;
      if (index.events.length > retainedEvents) index.events.splice(0, index.events.length - retainedEvents);
      saveIndex(tenant, index);
      return { accepted: true, duplicate: false, attestation: publicAttestation(stored) };
    });
  }

  function list(tenantId, { evidenceId = null, version = null, limit = 100 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    let rows = loadSafe(tenant).attestations;
    if (evidenceId !== null) rows = rows.filter((entry) => entry.evidenceId === evidenceIdentifier(evidenceId));
    if (version !== null) rows = rows.filter((entry) => entry.version === integer(version, 'version', 1, 1_000_000));
    return rows.slice(-integer(limit, 'limit', 1, 5000)).reverse().map(publicAttestation);
  }

  function latest(tenantId, evidenceId, version) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = evidenceIdentifier(evidenceId);
    const number = integer(version, 'version', 1, 1_000_000);
    const rows = loadSafe(tenant).attestations.filter((entry) => entry.evidenceId === id && entry.version === number);
    if (!rows.length) return null;
    rows.sort((left, right) => compareAttestationRecency(right, left));
    return publicAttestation(rows[0]);
  }

  function requireCleanForRelease(tenantId, evidenceId, version, contentSha256) {
    const attestation = latest(tenantId, evidenceId, version);
    if (!required || selectedMode !== 'enforce') return attestation;
    if (!attestation || attestation.contentSha256 !== contentSha256 || attestation.verdict !== 'clean') {
      throw new ExternalScanRequiredError(evidenceId, { version, latestVerdict: attestation?.verdict ?? null });
    }
    const ageMinutes = (now().getTime() - new Date(attestation.scannedAt).getTime()) / 60_000;
    if (ageMinutes < -safeSkewSeconds / 60 || ageMinutes > safeMaxAgeMinutes) {
      throw new ExternalScanRequiredError(evidenceId, { version, reason: 'attestation_expired', scannedAt: attestation.scannedAt });
    }
    return attestation;
  }

  function verify(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    verifyChain(index);
    return { valid: true, tenantId: tenant, records: index.attestations.length, headSequence: index.sequence, headHash: index.headHash };
  }

  function tenantStatus(tenantId) {
    const index = loadSafe(identifier(tenantId, 'tenantId'));
    const latestByVersion = new Map();
    for (const entry of index.attestations) {
      const key = `${entry.evidenceId}:${entry.version}`;
      const current = latestByVersion.get(key);
      if (!current || compareAttestationRecency(entry, current) > 0) latestByVersion.set(key, entry);
    }
    const values = [...latestByVersion.values()];
    return {
      status: values.some((entry) => entry.verdict !== 'clean') ? 'attention' : 'ready',
      mode: selectedMode,
      requiredForRelease: required,
      totalAttestations: index.attestations.length,
      clean: values.filter((entry) => entry.verdict === 'clean').length,
      suspicious: values.filter((entry) => entry.verdict === 'suspicious').length,
      malicious: values.filter((entry) => entry.verdict === 'malicious').length,
      errors: values.filter((entry) => entry.verdict === 'error').length,
      headSequence: index.sequence,
      headHash: index.headHash
    };
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: 'ready', enabled: true, mode: selectedMode, requiredForRelease: required,
        durable: true, distributed: true, encrypted: true, providerCount: providerKeys.size,
        maxAttestationAgeMinutes: safeMaxAgeMinutes, clockSkewSeconds: safeSkewSeconds,
        eventRetention: retainedEvents, maxRecords: safeMaxRecords, mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: selectedMode, requiredForRelease: required, error: error?.code ?? 'external_scan_store_unavailable' };
    }
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) { if (error instanceof EvidenceIntegrityError || error instanceof ExternalScanStoreError) throw error; throw new ExternalScanStoreError(undefined, { tenantId: tenant }, error); }
  }
  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant);
    let envelope;
    try { envelope = readEvidenceJson(path); } catch (error) { throw new EvidenceIntegrityError('The external scan attestation index is unreadable.', { tenantId: tenant }, error); }
    const index = decryptEvidenceJson(envelope, keyring, aad(tenant), EvidenceIntegrityError);
    if (index.format !== FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.attestations)) {
      throw new EvidenceIntegrityError('The external scan attestation index identity is invalid.', { tenantId: tenant });
    }
    verifyChain(index);
    return index;
  }
  function saveIndex(tenant, index) { atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, keyring, aad(tenant))); }
  function indexPath(tenant) { return resolve(tenantEvidenceDirectory(root, tenant), 'attestations.evidence'); }

  return Object.freeze({
    enabled: true,
    mode: selectedMode,
    requiredForRelease: required,
    acceptSigned,
    list,
    latest,
    requireCleanForRelease,
    verify,
    tenantStatus,
    health,
    directory: root
  });
}

export function createExternalScanAttestationRegistryFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_MODE) ?? 'disabled';
  const requiredForRelease = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_REQUIRED_FOR_RELEASE) ?? false);
  if (mode === 'disabled') return createExternalScanAttestationRegistry({ mode, requiredForRelease });
  if (!evidenceRegistry?.enabled || !evidenceRegistry.directory) throw new ExternalScanStoreError('External scanner attestations require enabled evidence custody.');
  let keys;
  let providers;
  try {
    keys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
    providers = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS));
  } catch (error) {
    throw new ExternalScanStoreError('External scanner configuration JSON is invalid.', {}, error);
  }
  return createExternalScanAttestationRegistry({
    directory: evidenceRegistry.directory,
    keys,
    primaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
    providers,
    mode,
    requiredForRelease,
    maxAttestationAgeMinutes: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_MAX_AGE_MINUTES) ?? 1440,
    clockSkewSeconds: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_CLOCK_SKEW_SECONDS) ?? 300,
    eventRetention: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_EVENT_RETENTION) ?? 10_000,
    maxRecords: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_MAX_RECORDS) ?? 100_000
  });
}

function parseProviders(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('External scanner providers must be an object.');
  const providers = new Map();
  for (const [providerId, provider] of Object.entries(input)) {
    identifier(providerId, 'providerId');
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`External scanner provider ${providerId} must be an object.`);
    const rawKeys = provider.keys;
    if (!rawKeys || typeof rawKeys !== 'object' || Array.isArray(rawKeys)) throw new TypeError(`External scanner provider ${providerId} keys must be an object.`);
    const keyMap = new Map();
    for (const [keyId, encoded] of Object.entries(rawKeys)) {
      identifier(keyId, 'keyId');
      const secret = strictBase64(encoded, `external scanner key ${providerId}/${keyId}`);
      if (secret.length < 32 || secret.length > 128) throw new TypeError(`External scanner key ${providerId}/${keyId} must decode to 32 to 128 bytes.`);
      keyMap.set(keyId, secret);
    }
    if (!keyMap.size) throw new TypeError(`External scanner provider ${providerId} must contain at least one key.`);
    providers.set(providerId, keyMap);
  }
  return providers;
}

function normaliseAttestation(input, authentication, now) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('External scan attestation must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) {
    if (!ATTESTATION_FIELDS.has(key)) throw new EvidenceValidationError('External scan attestation contains an unsupported field.', { field: key });
  }
  const scannedAt = validDate(input.scannedAt, 'scannedAt');
  if (scannedAt.getTime() > now().getTime() + 3_600_000) throw new EvidenceValidationError('External scan time is unreasonably far in the future.', { field: 'scannedAt' });
  const findings = Array.isArray(input.findings) ? input.findings.map(normaliseFinding) : [];
  return {
    attestationId: attestationIdentifier(input.attestationId),
    tenantId: identifier(input.tenantId, 'tenantId'),
    evidenceId: evidenceIdentifier(input.evidenceId),
    version: integer(input.version, 'version', 1, 1_000_000),
    contentSha256: hashValue(input.contentSha256, 'contentSha256'),
    verdict: enumValue(input.verdict, VERDICTS, 'verdict'),
    scannedAt: scannedAt.toISOString(),
    engine: text(input.engine, 'engine', 2, 128),
    engineVersion: optionalText(input.engineVersion, 'engineVersion', 128),
    definitionsVersion: optionalText(input.definitionsVersion, 'definitionsVersion', 128),
    findings,
    providerId: authentication.providerId,
    keyId: authentication.keyId,
    signedAt: authentication.signedAt,
    nonce: authentication.nonce
  };
}

function normaliseFinding(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('External scan finding must be an object.', { field: 'findings' });
  const allowed = new Set(['ruleId', 'severity', 'category']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError('External scan findings may contain only ruleId, severity and category.', { field: `findings.${key}` });
  return {
    ruleId: text(input.ruleId, 'ruleId', 2, 128),
    severity: enumValue(input.severity, new Set(['info', 'low', 'medium', 'high', 'critical']), 'severity'),
    category: text(input.category, 'category', 2, 128)
  };
}

function verifyChain(index) {
  let previous = null;
  let sequence = 1;
  for (const entry of index.attestations) {
    if (entry.sequence !== sequence || entry.previousHash !== previous || entry.hash !== recordHash(entry)) {
      throw new EvidenceIntegrityError('The external scan attestation chain is invalid.', { attestationId: entry.attestationId, expectedSequence: sequence });
    }
    previous = entry.hash;
    sequence += 1;
  }
  if (index.sequence !== sequence - 1 || index.headHash !== previous) throw new EvidenceIntegrityError('The external scan attestation chain head is inconsistent.');
}

function publicAttestation(entry) {
  return {
    receiptId: entry.receiptId,
    attestationId: entry.attestationId,
    providerId: entry.providerId,
    keyId: entry.keyId,
    evidenceId: entry.evidenceId,
    version: entry.version,
    contentSha256: entry.contentSha256,
    verdict: entry.verdict,
    scannedAt: entry.scannedAt,
    receivedAt: entry.receivedAt,
    engine: entry.engine,
    engineVersion: entry.engineVersion,
    definitionsVersion: entry.definitionsVersion,
    findings: entry.findings.map((finding) => ({ ...finding })),
    sequence: entry.sequence,
    previousHash: entry.previousHash,
    hash: entry.hash
  };
}

function disabledRegistry() {
  return Object.freeze({
    enabled: false,
    mode: 'disabled',
    requiredForRelease: false,
    acceptSigned() { throw new EvidenceConflictError('External scanner attestations are disabled.'); },
    list() { return []; },
    latest() { return null; },
    requireCleanForRelease() { return null; },
    verify() { return { valid: true, disabled: true }; },
    tenantStatus() { return { status: 'disabled', mode: 'disabled', requiredForRelease: false, totalAttestations: 0 }; },
    health() { return { status: 'disabled', enabled: false, mode: 'disabled', requiredForRelease: false }; }
  });
}

function compareAttestationRecency(left, right) {
  const timestampDifference = new Date(left.scannedAt).getTime() - new Date(right.scannedAt).getTime();
  return timestampDifference || left.sequence - right.sequence;
}
function emptyIndex(tenantId) { return { format: FORMAT, version: 1, tenantId, createdAt: null, updatedAt: null, sequence: 0, headHash: null, eventSequence: 0, attestations: [], events: [] }; }
function attestationPayloadHash(value) { return sha256(Buffer.from(JSON.stringify({ tenantId: value.tenantId, evidenceId: value.evidenceId, version: value.version, contentSha256: value.contentSha256, verdict: value.verdict, scannedAt: value.scannedAt, engine: value.engine, engineVersion: value.engineVersion, definitionsVersion: value.definitionsVersion, findings: value.findings, providerId: value.providerId, keyId: value.keyId, signedAt: value.signedAt, nonce: value.nonce }))); }
function recordHash(value) { return sha256(Buffer.from(JSON.stringify({ receiptId: value.receiptId, attestationId: value.attestationId, providerId: value.providerId, keyId: value.keyId, evidenceId: value.evidenceId, version: value.version, contentSha256: value.contentSha256, verdict: value.verdict, scannedAt: value.scannedAt, receivedAt: value.receivedAt, engine: value.engine, engineVersion: value.engineVersion, definitionsVersion: value.definitionsVersion, findings: value.findings, sequence: value.sequence, previousHash: value.previousHash, payloadHash: value.payloadHash }))); }
function aad(tenant) { return `basitclaw:external-scan-attestations:${tenant}`; }
function header(headers, name) { const value = headers?.[name] ?? headers?.[name.toLowerCase()]; const clean = Array.isArray(value) ? value[0] : String(value ?? '').trim(); if (!clean) throw new ExternalScanAuthenticationError(); return clean; }
function evidenceIdentifier(value) { const clean = String(value ?? '').trim(); if (!EVIDENCE_ID.test(clean)) throw new EvidenceValidationError('evidenceId must be a valid EVD identifier.', { field: 'evidenceId' }); return clean; }
function attestationIdentifier(value) { const clean = String(value ?? '').trim(); if (!ATTESTATION_ID.test(clean)) throw new EvidenceValidationError('attestationId must be a safe identifier containing 8 to 128 characters.', { field: 'attestationId' }); return clean; }
function hashValue(value, field) { const clean = String(value ?? '').trim().toLowerCase(); if (!HASH.test(clean)) throw new EvidenceValidationError(`${field} must be a lowercase SHA-256 digest.`, { field }); return clean; }
function identifier(value, field) { const clean = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@-]{1,191}$/.test(clean)) throw new EvidenceValidationError(`${field} must be a safe identifier.`, { field }); return clean; }
function text(value, field, minimum, maximum) { const clean = String(value ?? '').trim(); if (clean.length < minimum || clean.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return clean; }
function optionalText(value, field, maximum) { if (value === undefined || value === null || value === '') return null; return text(value, field, 1, maximum); }
function validDate(value, field) { const date = new Date(value); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid timestamp.`, { field }); return date; }
function enumValue(value, allowed, field) { const clean = String(value ?? '').trim(); if (!allowed.has(clean)) throw new EvidenceValidationError(`${field} is invalid.`, { field, allowed: [...allowed] }); return clean; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be boolean.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
