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
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);

export class EvidencePreservationStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence preservation store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidencePreservationStoreError';
    this.code = 'EVIDENCE_PRESERVATION_STORE_UNAVAILABLE';
  }
}

export class EvidencePreservationIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence preservation integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidencePreservationIntegrityError';
    this.code = 'EVIDENCE_PRESERVATION_INTEGRITY_FAILED';
  }
}

export class EvidencePreservationRequiredError extends EvidenceConflictError {
  constructor(evidenceId, details = {}) {
    super('Every immutable evidence version must have a verified preservation receipt before disposition.', {
      evidenceId,
      ...details
    });
    this.name = 'EvidencePreservationRequiredError';
    this.code = 'EVIDENCE_PRESERVATION_REQUIRED';
  }
}

export function createEvidencePreservationStore({
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
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence preservation directory is required.');
  if (required && !backendConfirmed) {
    throw new TypeError('Required evidence preservation needs an explicitly confirmed immutable backend.');
  }

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const signing = parseSigningKeyring(signingSecrets, signingPrimaryKeyId);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function preserve(input, { actor, purpose } = {}) {
    const source = validateInput(input);
    const archivedBy = identifier(actor, 'actor');
    const archivePurpose = cleanText(purpose, 'purpose', 10, 500);
    const archiveId = archiveIdFor(source);
    const paths = archivePaths(source.tenantId, archiveId);

    return lock.withLock(`evidence-preservation:${source.tenantId}`, () => {
      const objectExists = existsSync(paths.object);
      const receiptExists = existsSync(paths.receipt);
      if (receiptExists && !objectExists) {
        throw new EvidencePreservationIntegrityError('A preservation receipt exists without its immutable object.', { archiveId });
      }
      if (objectExists) {
        const object = readObject(paths.object, source.tenantId, archiveId);
        assertObjectMatches(object, source);
        if (!receiptExists) {
          const receipt = makeReceipt(object, paths.object);
          writeRecord(paths.receipt, receipt, receiptAad(source.tenantId, archiveId));
          return { archived: true, duplicate: false, recoveredReceipt: true, receipt: publicReceipt(receipt) };
        }
        const verified = verifyLocked(source.tenantId, archiveId);
        assertReceiptMatches(verified.receipt, source);
        return { archived: false, duplicate: true, recoveredReceipt: false, receipt: verified.receipt };
      }

      const object = {
        format: OBJECT_FORMAT,
        version: 1,
        archiveId,
        tenantId: source.tenantId,
        evidenceId: source.evidenceId,
        evidenceVersion: source.version,
        filename: source.filename,
        mediaType: source.mediaType,
        contentSha256: source.contentSha256,
        sizeBytes: source.sizeBytes,
        retentionUntil: source.retentionUntil,
        legalHold: source.legalHold,
        archivedAt: now().toISOString(),
        archivedBy,
        purpose: archivePurpose,
        contentBase64: source.content.toString('base64')
      };
      writeRecord(paths.object, object, objectAad(source.tenantId, archiveId));
      const receipt = makeReceipt(object, paths.object);
      try {
        writeRecord(paths.receipt, receipt, receiptAad(source.tenantId, archiveId));
      } catch (error) {
        throw storeFailure(error, 'write_receipt', archiveId);
      }
      return { archived: true, duplicate: false, recoveredReceipt: false, receipt: publicReceipt(receipt) };
    });
  }

  function list(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    return lock.withLock(`evidence-preservation:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      return names(paths.receipts, '.receipt')
        .map((filename) => readReceipt(resolve(paths.receipts, filename), tenant, filename.slice(0, -8)))
        .filter((receipt) => !evidence || receipt.evidenceId === evidence)
        .sort((left, right) => right.archivedAt.localeCompare(left.archivedAt))
        .slice(0, integer(limit, 'limit', 1, 5000))
        .map(publicReceipt);
    });
  }

  function verify(tenantId, archiveId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = archiveIdentifier(archiveId);
    return lock.withLock(`evidence-preservation:${tenant}`, () => verifyLocked(tenant, id));
  }

  function verifyLocked(tenant, archiveId) {
    const paths = archivePaths(tenant, archiveId);
    if (!existsSync(paths.object) || !existsSync(paths.receipt)) {
      throw new EvidencePreservationIntegrityError('The preservation object or receipt is missing.', { archiveId });
    }
    const object = readObject(paths.object, tenant, archiveId);
    const receipt = readReceipt(paths.receipt, tenant, archiveId);
    const objectEnvelopeSha256 = envelopeHash(paths.object);
    if (receipt.objectEnvelopeSha256 !== objectEnvelopeSha256
        || receipt.evidenceId !== object.evidenceId
        || receipt.evidenceVersion !== object.evidenceVersion
        || receipt.contentSha256 !== object.contentSha256
        || receipt.sizeBytes !== object.sizeBytes
        || receipt.retentionUntil !== object.retentionUntil
        || receipt.archivedAt !== object.archivedAt) {
      throw new EvidencePreservationIntegrityError('The preservation receipt does not match its immutable object.', { archiveId });
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
    return lock.withLock(`evidence-preservation:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      let checkedArchives = 0;
      for (const filename of names(paths.receipts, '.receipt')) {
        verifyLocked(tenant, filename.slice(0, -8));
        checkedArchives += 1;
      }
      const orphanObjects = names(paths.objects, '.object')
        .filter((filename) => !existsSync(resolve(paths.receipts, `${filename.slice(0, -7)}.receipt`))).length;
      if (orphanObjects) {
        throw new EvidencePreservationIntegrityError('One or more preservation objects have no receipt.', { orphanObjects });
      }
      return { valid: true, tenantId: tenant, checkedArchives, orphanObjects: 0 };
    });
  }

  function verifiedForVersion(tenantId, evidenceId, version, contentSha256, minimumRetentionUntil) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceIdentifier(evidenceId);
    const evidenceVersion = integer(version, 'version', 1, 1_000_000);
    const digest = hashValue(contentSha256, 'contentSha256');
    const minimumRetention = isoDate(minimumRetentionUntil, 'minimumRetentionUntil');
    for (const receipt of list(tenant, { evidenceId: evidence, limit: 5000 })) {
      if (receipt.evidenceVersion !== evidenceVersion || receipt.contentSha256 !== digest) continue;
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
      const archives = names(paths.receipts, '.receipt').length;
      const objects = names(paths.objects, '.object').length;
      const orphanObjects = Math.max(0, objects - archives);
      return {
        status: orphanObjects ? 'unavailable' : backendConfirmed ? 'ready' : 'attention',
        enabled: true,
        requiredForDisposition: required,
        immutableBackendConfirmed: backendConfirmed,
        archives,
        orphanObjects
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        immutableBackendConfirmed: backendConfirmed,
        error: error?.code ?? 'evidence_preservation_store_unavailable'
      };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(root, { withFileTypes: true })
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
        tenantDirectoryCount,
        mutex: lock.health()
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        requiredForDisposition: required,
        mode: 'shared-file-write-once-preservation',
        error: error?.code ?? 'evidence_preservation_store_unavailable'
      };
    }
  }

  function writeRecord(path, payload, aad) {
    let envelope;
    try { envelope = encryptEvidenceJson(payload, encryption, aad); }
    catch (error) { throw storeFailure(error, 'encrypt', payload.archiveId); }
    writeJsonExclusive(path, envelope, payload.archiveId);
  }

  function readObject(path, tenant, archiveId) {
    const object = readRecord(path, objectAad(tenant, archiveId), archiveId, 'object');
    if (!object || object.format !== OBJECT_FORMAT || object.version !== 1
        || object.archiveId !== archiveId || object.tenantId !== tenant
        || !EVIDENCE_ID.test(object.evidenceId) || !HASH.test(object.contentSha256)) {
      throw new EvidencePreservationIntegrityError('A preservation object has an invalid identity.', { archiveId });
    }
    let content;
    try { content = strictBase64(object.contentBase64, 'preserved content'); }
    catch (error) { throw new EvidencePreservationIntegrityError('Preserved evidence content is invalid.', { archiveId }, error); }
    if (content.length !== object.sizeBytes || sha256(content) !== object.contentSha256) {
      throw new EvidencePreservationIntegrityError('Preserved evidence content checksum verification failed.', { archiveId });
    }
    return object;
  }

  function readReceipt(path, tenant, archiveId) {
    const receipt = readRecord(path, receiptAad(tenant, archiveId), archiveId, 'receipt');
    if (!receipt || receipt.format !== RECEIPT_FORMAT || receipt.version !== 1
        || receipt.archiveId !== archiveId || receipt.tenantId !== tenant) {
      throw new EvidencePreservationIntegrityError('A preservation receipt has an invalid identity.', { archiveId });
    }
    verifySignature(receipt, signing);
    return receipt;
  }

  function readRecord(path, aad, archiveId, kind) {
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidencePreservationStoreError(`A preservation ${kind} is unreadable.`, { archiveId }, error); }
    return decryptEvidenceJson(envelope, encryption, aad, EvidencePreservationIntegrityError);
  }

  function makeReceipt(object, objectPath) {
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
      objectEnvelopeSha256: envelopeHash(objectPath),
      retentionUntil: object.retentionUntil,
      legalHoldActive: Boolean(object.legalHold?.active),
      archivedAt: object.archivedAt,
      archivedBy: object.archivedBy,
      purpose: object.purpose,
      immutabilityMode: backendConfirmed ? 'backend-confirmed-write-once' : 'application-write-once'
    };
    return signReceipt(body, signing);
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
    return { objects, receipts };
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

export function createEvidencePreservationStoreFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_MODE) ?? 'disabled';
  const requiredForDisposition = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_REQUIRED_FOR_DISPOSITION) ?? false);
  if (mode === 'disabled') return createEvidencePreservationStore({ mode, requiredForDisposition });
  if (!evidenceRegistry?.enabled || !evidenceRegistry.directory) {
    throw new EvidencePreservationStoreError('Evidence preservation requires enabled evidence custody.');
  }
  try {
    const encryptionKeys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_KEYS)
      ?? environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
    const signingSecrets = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_SIGNING_SECRETS));
    return createEvidencePreservationStore({
      mode,
      requiredForDisposition,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_DIR)
        ?? resolve(evidenceRegistry.directory, '.preservation'),
      encryptionKeys,
      encryptionPrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_PRIMARY_KEY_ID)
        ?? environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      signingSecrets,
      signingPrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_PRIMARY_SIGNING_KEY_ID),
      immutableBackendConfirmed: parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_IMMUTABLE_BACKEND_CONFIRMED) ?? false)
    });
  } catch (error) {
    if (error instanceof EvidencePreservationStoreError) throw error;
    throw new EvidencePreservationStoreError('Evidence preservation configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid evidence preservation record is required.');
  if (!Buffer.isBuffer(input.content)) throw new EvidenceValidationError('Preservation content must be a Buffer.', { field: 'content' });
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const version = integer(input.version, 'version', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const sizeBytes = integer(input.sizeBytes, 'sizeBytes', 0, 100_000_000);
  if (sha256(input.content) !== contentSha256 || input.content.length !== sizeBytes) {
    throw new EvidencePreservationIntegrityError('Preservation content does not match its immutable evidence metadata.', { evidenceId, version });
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

function assertObjectMatches(object, input) {
  if (object.tenantId !== input.tenantId || object.evidenceId !== input.evidenceId
      || object.evidenceVersion !== input.version || object.contentSha256 !== input.contentSha256
      || object.sizeBytes !== input.sizeBytes || object.retentionUntil !== input.retentionUntil) {
    throw new EvidencePreservationIntegrityError('An existing preservation object conflicts with the requested immutable version.', { archiveId: object.archiveId });
  }
}

function assertReceiptMatches(receipt, input) {
  if (receipt.evidenceId !== input.evidenceId || receipt.evidenceVersion !== input.version
      || receipt.contentSha256 !== input.contentSha256 || receipt.sizeBytes !== input.sizeBytes
      || receipt.retentionUntil !== input.retentionUntil) {
    throw new EvidencePreservationIntegrityError('An existing preservation receipt conflicts with the requested immutable version.', { archiveId: receipt.archiveId });
  }
}

function archiveIdFor(input) {
  return `ARC-${sha256([
    input.tenantId,
    input.evidenceId,
    String(input.version),
    input.contentSha256,
    input.retentionUntil
  ].join('|')).slice(0, 32)}`;
}

function parseSigningKeyring(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Evidence preservation signing secrets must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 100) throw new TypeError('Evidence preservation signing secrets must contain 1 to 100 entries.');
  const keys = new Map(entries.map(([keyId, encoded]) => {
    safeKeyId(keyId);
    const secret = strictBase64(encoded, `signing secret ${keyId}`);
    if (secret.length < 32 || secret.length > 128) throw new TypeError(`Evidence preservation signing secret ${keyId} must decode to 32 to 128 bytes.`);
    return [keyId, secret];
  }));
  const primary = String(primaryKeyId ?? entries[0][0]);
  if (!keys.has(primary)) throw new TypeError('The evidence preservation primary signing key ID is not present in the keyring.');
  return Object.freeze({ keys, primaryKeyId: primary });
}

function signReceipt(body, keyring) {
  const signingKeyId = keyring.primaryKeyId;
  const signature = createHmac('sha256', keyring.keys.get(signingKeyId)).update(stableStringify(body)).digest('base64');
  return { ...body, signingKeyId, signature };
}

function verifySignature(receipt, keyring) {
  const key = keyring.keys.get(receipt.signingKeyId);
  if (!key) throw new EvidencePreservationIntegrityError('The preservation receipt references an unavailable signing key.', { signingKeyId: receipt.signingKeyId });
  const { signingKeyId, signature, ...body } = receipt;
  const expected = createHmac('sha256', key).update(stableStringify(body)).digest();
  let supplied;
  try { supplied = strictBase64(signature, 'receipt signature'); }
  catch (error) { throw new EvidencePreservationIntegrityError('The preservation receipt signature is invalid.', { signingKeyId }, error); }
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
    throw new EvidencePreservationIntegrityError('The preservation receipt signature verification failed.', { signingKeyId });
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

function writeJsonExclusive(path, value, archiveId) {
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
    if (error?.code === 'EEXIST') {
      throw new EvidencePreservationIntegrityError('A conflicting write-once preservation record already exists.', { archiveId });
    }
    throw new EvidencePreservationStoreError('A write-once preservation record could not be committed.', { archiveId }, error);
  }
}

function envelopeHash(path) {
  try { return sha256(Buffer.from(JSON.stringify(JSON.parse(readFileSync(path, 'utf8'))))); }
  catch (error) { throw new EvidencePreservationStoreError('A preservation envelope cannot be canonicalised.', {}, error); }
}

function names(directory, suffix) {
  return readdirSync(directory).filter((name) => ARCHIVE_ID.test(name.slice(0, -suffix.length)) && name.endsWith(suffix)).sort();
}
function objectAad(tenantId, archiveId) { return `basitclaw:evidence-preservation:object:${tenantId}:${archiveId}`; }
function receiptAad(tenantId, archiveId) { return `basitclaw:evidence-preservation:receipt:${tenantId}:${archiveId}`; }
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
function safeKeyId(value) { if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(String(value ?? ''))) throw new TypeError('signingKeyId must be a safe identifier.'); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function storeFailure(error, operation, archiveId) { if (error instanceof EvidencePreservationStoreError || error instanceof EvidencePreservationIntegrityError) return error; return new EvidencePreservationStoreError('The evidence preservation operation failed.', { operation, archiveId }, error); }

function disabledStore() {
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
