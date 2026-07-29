import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256,
  strictBase64
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const OBJECT_FORMAT = 'basitclaw-evidence-preservation-object';
const RECEIPT_FORMAT = 'basitclaw-evidence-preservation-receipt';
const MODES = new Set(['disabled', 'shared-file']);
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const DAY_MS = 86_400_000;

export class EvidenceArchiveStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence preservation archive is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceArchiveStoreError';
    this.code = 'EVIDENCE_ARCHIVE_STORE_UNAVAILABLE';
  }
}

export class EvidenceArchiveIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence preservation archive integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceArchiveIntegrityError';
    this.code = 'EVIDENCE_ARCHIVE_INTEGRITY_FAILED';
  }
}

export class EvidenceArchiveRequiredError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('Every immutable evidence version must have a verified preservation receipt before disposition.', {
      evidenceId,
      ...details
    });
    this.name = 'EvidenceArchiveRequiredError';
    this.code = 'EVIDENCE_ARCHIVE_REQUIRED';
  }
}

export function createEvidenceArchiveStore({
  mode = 'disabled',
  requiredForDisposition = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  signingSecrets,
  signingPrimaryKeyId,
  immutableBackendConfirmed = false,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const required = booleanValue(requiredForDisposition, 'requiredForDisposition');
  const backendConfirmed = booleanValue(immutableBackendConfirmed, 'immutableBackendConfirmed');
  if (selectedMode === 'disabled') {
    if (required) throw new TypeError('Required evidence preservation cannot be disabled.');
    return disabledArchiveStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence preservation archive directory is required.');
  if (required && !backendConfirmed) {
    throw new TypeError('Required evidence preservation needs an explicitly confirmed immutable backend.');
  }

  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const signing = parseSigningKeyring(signingSecrets, signingPrimaryKeyId);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function preserve(input, { actor, purpose } = {}) {
    const record = validatePreservationInput(input);
    const archivedBy = identifier(actor, 'actor');
    const archivePurpose = cleanText(purpose, 'purpose', 10, 500);
    const archiveId = archiveIdFor(record);
    const paths = archivePaths(record.tenantId, archiveId);

    return lock.withLock(`evidence-archive:${record.tenantId}`, () => {
      const objectExists = existsSync(paths.object);
      const receiptExists = existsSync(paths.receipt);
      if (receiptExists && !objectExists) {
        throw new EvidenceArchiveIntegrityError('A preservation receipt exists without its immutable object.', { archiveId });
      }
      if (objectExists) {
        const object = readAndVerifyObject(paths.object, record.tenantId, archiveId);
        assertObjectMatchesInput(object, record);
        if (!receiptExists) {
          const receipt = createReceipt(object, paths.object, { archivedBy: object.archivedBy, purpose: object.purpose });
          writeEncryptedExclusive(paths.receipt, receipt, receiptAad(record.tenantId, archiveId));
          return { archived: true, duplicate: false, recoveredReceipt: true, receipt: publicReceipt(receipt) };
        }
        const verified = verifyLocked(record.tenantId, archiveId);
        assertReceiptMatchesInput(verified.receipt, record);
        return { archived: false, duplicate: true, recoveredReceipt: false, receipt: verified.receipt };
      }

      const archivedAt = now().toISOString();
      const object = {
        format: OBJECT_FORMAT,
        version: 1,
        archiveId,
        tenantId: record.tenantId,
        evidenceId: record.evidenceId,
        evidenceVersion: record.version,
        filename: record.filename,
        mediaType: record.mediaType,
        contentSha256: record.contentSha256,
        sizeBytes: record.sizeBytes,
        retentionUntil: record.retentionUntil,
        legalHold: structuredClone(record.legalHold),
        archivedAt,
        archivedBy,
        purpose: archivePurpose,
        contentBase64: record.content.toString('base64')
      };
      writeEncryptedExclusive(paths.object, object, objectAad(record.tenantId, archiveId));
      try {
        const receipt = createReceipt(object, paths.object, { archivedBy, purpose: archivePurpose });
        writeEncryptedExclusive(paths.receipt, receipt, receiptAad(record.tenantId, archiveId));
        return { archived: true, duplicate: false, recoveredReceipt: false, receipt: publicReceipt(receipt) };
      } catch (error) {
        throw archiveFailure(error, 'write_receipt', archiveId);
      }
    });
  }

  function list(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    return lock.withLock(`evidence-archive:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      const receipts = archiveNames(paths.receipts)
        .map((filename) => readAndVerifyReceipt(resolve(paths.receipts, filename), tenant, filename.slice(0, -8)))
        .filter((receipt) => !evidence || receipt.evidenceId === evidence)
        .sort((left, right) => right.archivedAt.localeCompare(left.archivedAt))
        .slice(0, integer(limit, 'limit', 1, 5000))
        .map(publicReceipt);
      return receipts;
    });
  }

  function verify(tenantId, archiveId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = archiveIdentifier(archiveId);
    return lock.withLock(`evidence-archive:${tenant}`, () => verifyLocked(tenant, id));
  }

  function verifyLocked(tenant, archiveId) {
    const paths = archivePaths(tenant, archiveId);
    if (!existsSync(paths.object) || !existsSync(paths.receipt)) {
      throw new EvidenceArchiveIntegrityError('The preservation object or receipt is missing.', { archiveId });
    }
    const object = readAndVerifyObject(paths.object, tenant, archiveId);
    const receipt = readAndVerifyReceipt(paths.receipt, tenant, archiveId);
    const envelopeHash = sha256(Buffer.from(canonicalEnvelope(paths.object)));
    if (receipt.objectEnvelopeSha256 !== envelopeHash
        || receipt.evidenceId !== object.evidenceId
        || receipt.evidenceVersion !== object.evidenceVersion
        || receipt.contentSha256 !== object.contentSha256
        || receipt.sizeBytes !== object.sizeBytes
        || receipt.retentionUntil !== object.retentionUntil
        || receipt.archivedAt !== object.archivedAt) {
      throw new EvidenceArchiveIntegrityError('The preservation receipt does not match its immutable object.', { archiveId });
    }
    return {
      valid: true,
      archiveId,
      receipt: publicReceipt(receipt),
      object: {
        contentSha256: object.contentSha256,
        sizeBytes: object.sizeBytes,
        encryptionKeyId: readEvidenceJson(paths.object).keyId
      }
    };
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`evidence-archive:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      let checkedArchives = 0;
      for (const filename of archiveNames(paths.receipts)) {
        verifyLocked(tenant, filename.slice(0, -8));
        checkedArchives += 1;
      }
      const orphanObjects = archiveNames(paths.objects)
        .filter((filename) => !existsSync(resolve(paths.receipts, `${filename.slice(0, -7)}.receipt`))).length;
      if (orphanObjects) {
        throw new EvidenceArchiveIntegrityError('One or more preservation objects have no receipt.', { orphanObjects });
      }
      return { valid: true, tenantId: tenant, checkedArchives, orphanObjects: 0 };
    });
  }

  function verifiedForVersion(tenantId, evidenceId, version, contentSha256, minimumRetentionUntil) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceIdentifier(evidenceId);
    const number = integer(version, 'version', 1, 1_000_000);
    const digest = hashValue(contentSha256, 'contentSha256');
    const minimumRetention = isoDate(minimumRetentionUntil, 'minimumRetentionUntil');
    const rows = list(tenant, { evidenceId: evidence, limit: 5000 });
    for (const receipt of rows) {
      if (receipt.evidenceVersion !== number || receipt.contentSha256 !== digest) continue;
      if (new Date(receipt.retentionUntil) < new Date(minimumRetention)) continue;
      verify(tenant, receipt.archiveId);
      return receipt;
    }
    return null;
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const paths = tenantPaths(tenant);
      const receipts = archiveNames(paths.receipts).length;
      const objects = archiveNames(paths.objects).length;
      const orphanObjects = Math.max(0, objects - receipts);
      return {
        status: orphanObjects ? 'unavailable' : backendConfirmed ? 'ready' : 'attention',
        enabled: true,
        requiredForDisposition: required,
        immutableBackendConfirmed: backendConfirmed,
        archives: receipts,
        orphanObjects
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        immutableBackendConfirmed: backendConfirmed,
        error: error?.code ?? 'evidence_archive_store_unavailable'
      };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenantDirectories = readdirSync(root, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && entry.name !== '.locks').length;
      return {
        status: backendConfirmed ? 'ready' : 'attention',
        enabled: true,
        requiredForDisposition: required,
        mode: 'shared-file-write-once-preservation',
        durable: true,
        encrypted: true,
        signedReceipts: true,
        createOnly: true,
        deletionApi: false,
        immutableBackendConfirmed: backendConfirmed,
        tenantDirectoryCount: tenantDirectories,
        mutex: lock.health()
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        mode: 'shared-file-write-once-preservation',
        error: error?.code ?? 'evidence_archive_store_unavailable'
      };
    }
  }

  function createReceipt(object, objectPath, { archivedBy, purpose }) {
    const body = {
      format: RECEIPT_FORMAT,
      version: 1,
      receiptId: `PRR-${sha256(`${object.archiveId}|${object.archivedAt}`).slice(0, 32)}`,
      archiveId: object.archiveId,
      tenantId: object.tenantId,
      evidenceId: object.evidenceId,
      evidenceVersion: object.evidenceVersion,
      contentSha256: object.contentSha256,
      sizeBytes: object.sizeBytes,
      objectEnvelopeSha256: sha256(Buffer.from(canonicalEnvelope(objectPath))),
      retentionUntil: object.retentionUntil,
      legalHoldActive: Boolean(object.legalHold?.active),
      archivedAt: object.archivedAt,
      archivedBy,
      purpose,
      immutabilityMode: backendConfirmed ? 'backend-confirmed-write-once' : 'application-write-once'
    };
    return signReceipt(body, signing);
  }

  function readAndVerifyObject(path, tenant, archiveId) {
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceArchiveStoreError('A preservation object is unreadable.', { archiveId }, error); }
    const object = decryptEvidenceJson(envelope, keyring, objectAad(tenant, archiveId), EvidenceArchiveIntegrityError);
    if (!object || object.format !== OBJECT_FORMAT || object.version !== 1
        || object.archiveId !== archiveId || object.tenantId !== tenant
        || !EVIDENCE_ID.test(object.evidenceId) || !HASH.test(object.contentSha256)) {
      throw new EvidenceArchiveIntegrityError('A preservation object has an invalid identity.', { archiveId });
    }
    let content;
    try { content = strictBase64(object.contentBase64, 'preserved content'); }
    catch (error) { throw new EvidenceArchiveIntegrityError('Preserved evidence content is invalid.', { archiveId }, error); }
    if (content.length !== object.sizeBytes || sha256(content) !== object.contentSha256) {
      throw new EvidenceArchiveIntegrityError('Preserved evidence content checksum verification failed.', { archiveId });
    }
    return object;
  }

  function readAndVerifyReceipt(path, tenant, archiveId) {
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceArchiveStoreError('A preservation receipt is unreadable.', { archiveId }, error); }
    const receipt = decryptEvidenceJson(envelope, keyring, receiptAad(tenant, archiveId), EvidenceArchiveIntegrityError);
    if (!receipt || receipt.format !== RECEIPT_FORMAT || receipt.version !== 1
        || receipt.archiveId !== archiveId || receipt.tenantId !== tenant) {
      throw new EvidenceArchiveIntegrityError('A preservation receipt has an invalid identity.', { archiveId });
    }
    verifyReceiptSignature(receipt, signing);
    return receipt;
  }

  function archivePaths(tenant, archiveId) {
    const paths = tenantPaths(tenant);
    return {
      object: resolve(paths.objects, `${archiveId}.object`),
      receipt: resolve(paths.receipts, `${archiveId}.receipt`)
    };
  }

  function tenantPaths(tenant) {
    const tenantRoot = resolve(root, sha256(tenant));
    const objects = resolve(tenantRoot, 'objects');
    const receipts = resolve(tenantRoot, 'receipts');
    mkdirSync(objects, { recursive: true, mode: 0o700 });
    mkdirSync(receipts, { recursive: true, mode: 0o700 });
    return { tenantRoot, objects, receipts };
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    requiredForDisposition: required,
    immutableBackendConfirmed: backendConfirmed,
    directory: root,
    preserve,
    list,
    verify,
    verifyTenant,
    verifiedForVersion,
    tenantStatus,
    health
  });
}

export function createEvidenceArchiveStoreFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_MODE) ?? 'disabled';
  const requiredForDisposition = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_REQUIRED_FOR_DISPOSITION) ?? false);
  if (mode === 'disabled') return createEvidenceArchiveStore({ mode, requiredForDisposition });
  if (!evidenceRegistry?.enabled || !evidenceRegistry.directory) {
    throw new EvidenceArchiveStoreError('Evidence preservation requires enabled evidence custody.');
  }
  try {
    const encryptionKeys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_KEYS)
      ?? environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
    const signingSecrets = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_SIGNING_SECRETS));
    return createEvidenceArchiveStore({
      mode,
      requiredForDisposition,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_DIR)
        ?? resolve(evidenceRegistry.directory, '.preservation-archive'),
      encryptionKeys,
      encryptionPrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_PRIMARY_KEY_ID)
        ?? environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      signingSecrets,
      signingPrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_PRIMARY_SIGNING_KEY_ID),
      immutableBackendConfirmed: parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_ARCHIVE_IMMUTABLE_BACKEND_CONFIRMED) ?? false)
    });
  } catch (error) {
    if (error instanceof EvidenceArchiveStoreError) throw error;
    throw new EvidenceArchiveStoreError('Evidence preservation configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function validatePreservationInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid evidence preservation record is required.');
  if (!Buffer.isBuffer(input.content)) throw new EvidenceValidationError('Preservation content must be a Buffer.', { field: 'content' });
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const version = integer(input.version, 'version', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const sizeBytes = integer(input.sizeBytes, 'sizeBytes', 0, 100_000_000);
  if (sha256(input.content) !== contentSha256 || input.content.length !== sizeBytes) {
    throw new EvidenceArchiveIntegrityError('Preservation content does not match its immutable evidence metadata.', { evidenceId, version });
  }
  return {
    tenantId,
    evidenceId,
    version,
    filename: cleanText(input.filename, 'filename', 1, 255),
    mediaType: cleanText(input.mediaType, 'mediaType', 1, 255),
    contentSha256,
    sizeBytes,
    retentionUntil: isoDate(input.retentionUntil, 'retentionUntil'),
    legalHold: normaliseLegalHold(input.legalHold),
    content: Buffer.from(input.content)
  };
}

function assertObjectMatchesInput(object, input) {
  if (object.tenantId !== input.tenantId || object.evidenceId !== input.evidenceId
      || object.evidenceVersion !== input.version || object.contentSha256 !== input.contentSha256
      || object.sizeBytes !== input.sizeBytes || object.retentionUntil !== input.retentionUntil) {
    throw new EvidenceArchiveIntegrityError('An existing preservation object conflicts with the requested immutable version.', { archiveId: object.archiveId });
  }
}

function assertReceiptMatchesInput(receipt, input) {
  if (receipt.evidenceId !== input.evidenceId || receipt.evidenceVersion !== input.version
      || receipt.contentSha256 !== input.contentSha256 || receipt.sizeBytes !== input.sizeBytes
      || receipt.retentionUntil !== input.retentionUntil) {
    throw new EvidenceArchiveIntegrityError('An existing preservation receipt conflicts with the requested immutable version.', { archiveId: receipt.archiveId });
  }
}

function archiveIdFor(record) {
  return `ARC-${sha256([
    record.tenantId,
    record.evidenceId,
    String(record.version),
    record.contentSha256,
    record.retentionUntil
  ].join('|')).slice(0, 32)}`;
}

function parseSigningKeyring(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Evidence archive signing secrets must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 100) throw new TypeError('Evidence archive signing secrets must contain 1 to 100 entries.');
  const keys = new Map(entries.map(([keyId, encoded]) => {
    identifier(keyId, 'signingKeyId');
    const secret = strictBase64(encoded, `signing secret ${keyId}`);
    if (secret.length < 32 || secret.length > 128) throw new TypeError(`Evidence archive signing secret ${keyId} must decode to 32 to 128 bytes.`);
    return [keyId, secret];
  }));
  const primary = String(primaryKeyId ?? entries[0][0]);
  if (!keys.has(primary)) throw new TypeError('The evidence archive primary signing key ID is not present in the keyring.');
  return Object.freeze({ keys, primaryKeyId: primary });
}

function signReceipt(body, keyring) {
  const signingKeyId = keyring.primaryKeyId;
  const signature = createHmac('sha256', keyring.keys.get(signingKeyId))
    .update(stableStringify(body))
    .digest('base64');
  return { ...body, signingKeyId, signature };
}

function verifyReceiptSignature(receipt, keyring) {
  const key = keyring.keys.get(receipt.signingKeyId);
  if (!key) throw new EvidenceArchiveIntegrityError('The preservation receipt references an unavailable signing key.', { signingKeyId: receipt.signingKeyId });
  const { signingKeyId, signature, ...body } = receipt;
  const expected = createHmac('sha256', key).update(stableStringify(body)).digest();
  let supplied;
  try { supplied = strictBase64(signature, 'receipt signature'); }
  catch (error) { throw new EvidenceArchiveIntegrityError('The preservation receipt signature is invalid.', { signingKeyId }, error); }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new EvidenceArchiveIntegrityError('The preservation receipt signature verification failed.', { signingKeyId });
  }
}

function publicReceipt(receipt) {
  return {
    receiptId: receipt.receiptId,
    archiveId: receipt.archiveId,
    evidenceId: receipt.evidenceId,
    evidenceVersion: receipt.evidenceVersion,
    contentSha256: receipt.contentSha256,
    sizeBytes: receipt.sizeBytes,
    objectEnvelopeSha256: receipt.objectEnvelopeSha256,
    retentionUntil: receipt.retentionUntil,
    legalHoldActive: receipt.legalHoldActive,
    archivedAt: receipt.archivedAt,
    archivedBy: receipt.archivedBy,
    purpose: receipt.purpose,
    immutabilityMode: receipt.immutabilityMode,
    signingKeyId: receipt.signingKeyId,
    signature: receipt.signature
  };
}

function writeEncryptedExclusive(path, payload, aad) {
  const envelope = encryptEvidenceJson(payload, this?.keyring ?? null, aad);
  return writeJsonExclusive(path, envelope);
}

function writeJsonExclusive(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor = null;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    if (error?.code !== 'EEXIST') try { rmSync(path, { force: true }); } catch {}
    throw error;
  }
}

function canonicalEnvelope(path) {
  try { return JSON.stringify(JSON.parse(readFileSync(path, 'utf8'))); }
  catch (error) { throw new EvidenceArchiveStoreError('A preservation envelope cannot be canonicalised.', {}, error); }
}

function objectAad(tenantId, archiveId) { return `basitclaw:evidence-preservation:object:${tenantId}:${archiveId}`; }
function receiptAad(tenantId, archiveId) { return `basitclaw:evidence-preservation:receipt:${tenantId}:${archiveId}`; }
function archiveNames(directory) { return readdirSync(directory).filter((name) => /^ARC-[a-f0-9]{32}\.(?:object|receipt)$/.test(name)).sort(); }
function archiveIdentifier(value) { const id = String(value ?? ''); if (!ARCHIVE_ID.test(id)) throw new EvidenceValidationError('archiveId is invalid.', { field: 'archiveId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function normaliseLegalHold(value) { if (!value) return { active: false, placedAt: null, reviewAt: null }; return { active: Boolean(value.active), placedAt: value.placedAt ? isoDate(value.placedAt, 'legalHold.placedAt') : null, reviewAt: value.reviewAt ? isoDate(value.reviewAt, 'legalHold.reviewAt') : null }; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be true or false.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function archiveFailure(error, operation, archiveId) { if (error instanceof EvidenceArchiveStoreError || error instanceof EvidenceArchiveIntegrityError) return error; if (error?.code === 'EEXIST') return new EvidenceArchiveIntegrityError('A conflicting write-once preservation record already exists.', { archiveId }); return new EvidenceArchiveStoreError('The evidence preservation archive operation failed.', { operation, archiveId }, error); }

function disabledArchiveStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, requiredForDisposition: false, mode: 'disabled', immutableBackendConfirmed: false });
  return Object.freeze({
    mode: 'disabled', enabled: false, requiredForDisposition: false, immutableBackendConfirmed: false,
    preserve() { throw new EvidenceConflictError('Evidence preservation is disabled.'); },
    list() { return []; },
    verify() { throw new EvidenceConflictError('Evidence preservation is disabled.'); },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedArchives: 0, orphanObjects: 0 }; },
    verifiedForVersion() { return null; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}
