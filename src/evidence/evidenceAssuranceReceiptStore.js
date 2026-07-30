import { constants, createPublicKey, verify } from 'node:crypto';
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
  atomicWriteEvidenceJson,
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

const RECEIPT_FORMAT = 'basitclaw-assurance-delivery-receipt-v1';
const RECORD_FORMAT = 'basitclaw-assurance-delivery-receipt-record';
const INDEX_FORMAT = 'basitclaw-assurance-delivery-receipt-index';
const BUNDLE_ID = /^ASB-[a-f0-9]{32}$/;
const RECEIPT_ID = /^ADR-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);

export class EvidenceAssuranceReceiptStoreError extends EvidenceStoreError {
  constructor(message = 'The assurance delivery receipt store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceReceiptStoreError';
    this.code = 'EVIDENCE_ASSURANCE_RECEIPT_STORE_UNAVAILABLE';
  }
}
export class EvidenceAssuranceReceiptIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Assurance delivery receipt integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceReceiptIntegrityError';
    this.code = 'EVIDENCE_ASSURANCE_RECEIPT_INTEGRITY_FAILED';
  }
}
export class EvidenceAssuranceReceiptSignatureError extends EvidenceConflictError {
  constructor(message = 'The assurance delivery receipt signature is invalid.', details = {}) {
    super(message, details);
    this.name = 'EvidenceAssuranceReceiptSignatureError';
    this.code = 'EVIDENCE_ASSURANCE_RECEIPT_SIGNATURE_INVALID';
    this.statusCode = 401;
  }
}

export function createEvidenceAssuranceReceiptStore({
  mode = 'disabled',
  required = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  recipients = {},
  maximumRecords = 100_000,
  clockSkewSeconds = 300,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required assurance delivery receipts cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An assurance delivery receipt directory is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const recipientKeys = parseReceiptRecipients(recipients);
  if (!recipientKeys.size) throw new TypeError('At least one recipient receipt-verification key is required.');
  const maximum = integer(maximumRecords, 'maximumRecords', 100, 1_000_000);
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 10, 3600) * 1000;
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function verifyAndRecord(input) {
    const source = validateInput(input);
    verifyIncomingSignature(source);
    const receiptTime = new Date(source.receivedAt);
    const current = now();
    if (receiptTime.getTime() > current.getTime() + skewMs
        || receiptTime.getTime() < new Date(source.claimedAt).getTime() - skewMs) {
      throw new EvidenceAssuranceReceiptSignatureError('The receipt time is outside the accepted delivery window.', {
        reason: 'receipt_time_window'
      });
    }

    return lock.withLock(`assurance-receipts:${source.tenantId}`, () => {
      const index = loadIndex(source.tenantId);
      const existing = index.receipts.find((entry) => entry.bundleId === source.bundleId);
      if (existing) {
        const record = readRecord(source.tenantId, existing.receiptId);
        assertSameReceipt(record, source);
        return { duplicate: true, recoveredIndex: false, receipt: publicReceipt(record) };
      }
      if (index.receipts.length >= maximum) {
        throw new EvidenceAssuranceReceiptStoreError('The assurance receipt journal reached its configured maximum.', {
          maximumRecords: maximum
        });
      }
      const canonical = receiptCanonical(source);
      const receiptId = `ADR-${sha256(canonical).slice(0, 32)}`;
      const path = receiptPath(source.tenantId, receiptId);
      if (existsSync(path)) {
        const record = readRecord(source.tenantId, receiptId);
        assertSameReceipt(record, source);
        assertRecoveryPosition(index, record);
        appendIndex(index, record);
        saveIndex(source.tenantId, index);
        return { duplicate: false, recoveredIndex: true, receipt: publicReceipt(record) };
      }
      const key = recipientKeys.get(source.recipientId).get(source.keyId);
      const previousHash = index.chainHead;
      const body = {
        format: RECORD_FORMAT,
        version: 1,
        receiptId,
        tenantId: source.tenantId,
        recipientId: source.recipientId,
        bundleId: source.bundleId,
        packageSha256: source.packageSha256,
        receivedAt: source.receivedAt,
        claimedAt: source.claimedAt,
        acknowledgedAt: current.toISOString(),
        keyId: source.keyId,
        algorithm: key.algorithm,
        publicKeyFingerprint: key.fingerprint,
        signature: source.signature,
        previousHash,
        sequence: index.receipts.length + 1
      };
      const recordHash = sha256(stableStringify(body));
      const record = { ...body, recordHash };
      writeRecordExclusive(path, record, source.tenantId, receiptId);
      appendIndex(index, record);
      saveIndex(source.tenantId, index);
      return { duplicate: false, recoveredIndex: false, receipt: publicReceipt(record) };
    });
  }

  function get(tenantId, bundleId) {
    const tenant = identifier(tenantId, 'tenantId');
    const bundle = bundleIdentifier(bundleId);
    return lock.withLock(`assurance-receipts:${tenant}`, () => {
      const entry = loadIndex(tenant).receipts.find((candidate) => candidate.bundleId === bundle);
      return entry ? publicReceipt(readRecord(tenant, entry.receiptId)) : null;
    });
  }
  function list(tenantId, { limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const maximumRows = integer(limit, 'limit', 1, 5000);
    return lock.withLock(`assurance-receipts:${tenant}`, () => loadIndex(tenant).receipts
      .slice().sort((left, right) => right.acknowledgedAt.localeCompare(left.acknowledgedAt))
      .slice(0, maximumRows).map((entry) => publicReceipt(readRecord(tenant, entry.receiptId))));
  }
  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`assurance-receipts:${tenant}`, () => {
      const index = loadIndex(tenant);
      let previousHash = null;
      let sequence = 0;
      for (const entry of index.receipts) {
        const record = readRecord(tenant, entry.receiptId);
        sequence += 1;
        if (record.sequence !== sequence || record.previousHash !== previousHash || record.recordHash !== entry.recordHash) {
          throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt chain is invalid.', {
            receiptId: entry.receiptId,
            sequence
          });
        }
        previousHash = record.recordHash;
      }
      const indexed = new Set(index.receipts.map((entry) => `${entry.receiptId}.receipt`));
      const orphanFiles = receiptNames(tenant).filter((name) => !indexed.has(name));
      if (orphanFiles.length) throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt journal contains unindexed records.', { orphanFiles: orphanFiles.length });
      if (index.chainHead !== previousHash) throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt chain head is invalid.');
      return { valid: true, tenantId: tenant, checkedReceipts: index.receipts.length, chainHead: index.chainHead };
    });
  }
  function tenantStatus(tenantId) {
    try {
      const result = verifyTenant(tenantId);
      return { status: 'ready', enabled: true, required: isRequired, receipts: result.checkedReceipts, chainHead: result.chainHead };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: isRequired, error: error?.code ?? 'assurance_receipt_store_unavailable' };
    }
  }
  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: 'ready', enabled: true, required: isRequired,
        mode: 'encrypted-recipient-signed-delivery-receipts',
        appendOnly: true, encrypted: true, hashChained: true,
        historicalSignaturesReverified: true,
        recipientCount: recipientKeys.size, maximumRecords: maximum,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: isRequired, error: error?.code ?? 'assurance_receipt_store_unavailable' };
    }
  }

  function verifyIncomingSignature(source) {
    const key = recipientKeys.get(source.recipientId)?.get(source.keyId);
    if (!key) throw new EvidenceAssuranceReceiptSignatureError(undefined, { reason: 'unknown_receipt_key' });
    const supplied = signatureBytes(source.signature);
    let valid = false;
    try { valid = verifySignature(receiptCanonical(source), supplied, key); }
    catch { throw new EvidenceAssuranceReceiptSignatureError('The receipt signature could not be verified.', { reason: 'signature_malformed' }); }
    if (!valid) throw new EvidenceAssuranceReceiptSignatureError(undefined, { reason: 'signature_mismatch' });
  }
  function assertStoredSignature(record) {
    const key = recipientKeys.get(record.recipientId)?.get(record.keyId);
    if (!key || key.algorithm !== record.algorithm || key.fingerprint !== record.publicKeyFingerprint) {
      throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt references an unavailable or changed verification key.', {
        receiptId: record.receiptId,
        recipientId: record.recipientId,
        keyId: record.keyId
      });
    }
    let supplied;
    try { supplied = strictBase64(record.signature, 'delivery receipt signature'); }
    catch (error) { throw new EvidenceAssuranceReceiptIntegrityError('The stored assurance receipt signature is malformed.', { receiptId: record.receiptId }, error); }
    let valid = false;
    try { valid = verifySignature(receiptCanonical(record), supplied, key); }
    catch (error) { throw new EvidenceAssuranceReceiptIntegrityError('The stored assurance receipt signature could not be verified.', { receiptId: record.receiptId }, error); }
    if (!valid) throw new EvidenceAssuranceReceiptIntegrityError('The stored assurance receipt signature verification failed.', { receiptId: record.receiptId });
  }
  function verifySignature(canonical, supplied, key) {
    return key.algorithm === 'ed25519'
      ? verify(null, Buffer.from(canonical), key.publicKey, supplied)
      : verify('sha256', Buffer.from(canonical), {
        key: key.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_DIGEST
      }, supplied);
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return { format: INDEX_FORMAT, version: 1, tenantId: tenant, receipts: [], chainHead: null };
    let index;
    try { index = decryptEvidenceJson(readEvidenceJson(path), encryption, indexAad(tenant), EvidenceAssuranceReceiptIntegrityError); }
    catch (error) { if (error instanceof EvidenceAssuranceReceiptIntegrityError) throw error; throw new EvidenceAssuranceReceiptStoreError('The assurance receipt index is unreadable.', {}, error); }
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.receipts)) {
      throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt index identity is invalid.');
    }
    return index;
  }
  function saveIndex(tenant, index) {
    try { atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, encryption, indexAad(tenant))); }
    catch (error) { throw new EvidenceAssuranceReceiptStoreError('The assurance receipt index could not be committed.', {}, error); }
  }
  function appendIndex(index, record) {
    index.receipts.push({
      receiptId: record.receiptId,
      bundleId: record.bundleId,
      recipientId: record.recipientId,
      packageSha256: record.packageSha256,
      receivedAt: record.receivedAt,
      acknowledgedAt: record.acknowledgedAt,
      recordHash: record.recordHash
    });
    index.chainHead = record.recordHash;
  }
  function assertRecoveryPosition(index, record) {
    if (record.previousHash !== index.chainHead || record.sequence !== index.receipts.length + 1) {
      throw new EvidenceAssuranceReceiptIntegrityError('An unindexed assurance receipt does not extend the current chain.', {
        receiptId: record.receiptId,
        expectedSequence: index.receipts.length + 1,
        actualSequence: record.sequence
      });
    }
  }
  function readRecord(tenant, receiptId) {
    const id = receiptIdentifier(receiptId);
    try {
      const record = decryptEvidenceJson(readEvidenceJson(receiptPath(tenant, id)), encryption, recordAad(tenant, id), EvidenceAssuranceReceiptIntegrityError);
      const { recordHash, ...body } = record ?? {};
      if (!record || record.format !== RECORD_FORMAT || record.version !== 1 || record.receiptId !== id
          || record.tenantId !== tenant || recordHash !== sha256(stableStringify(body))) {
        throw new EvidenceAssuranceReceiptIntegrityError('The assurance receipt record identity is invalid.', { receiptId: id });
      }
      assertStoredSignature(record);
      return record;
    } catch (error) {
      if (error instanceof EvidenceAssuranceReceiptIntegrityError) throw error;
      throw new EvidenceAssuranceReceiptStoreError('The assurance receipt record is unreadable.', { receiptId: id }, error);
    }
  }
  function writeRecordExclusive(path, record, tenant, receiptId) {
    const envelope = encryptEvidenceJson(record, encryption, recordAad(tenant, receiptId));
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    let descriptor = null;
    let created = false;
    let committed = false;
    try {
      descriptor = openSync(path, 'wx', 0o600);
      created = true;
      writeFileSync(descriptor, `${JSON.stringify(envelope)}\n`, 'utf8');
      fsyncSync(descriptor);
      closeSync(descriptor);
      descriptor = null;
      committed = true;
      fsyncDirectory(dirname(path));
    } catch (error) {
      if (descriptor !== null) try { closeSync(descriptor); } catch {}
      if (created && !committed) try { rmSync(path, { force: true }); } catch {}
      if (error?.code === 'EEXIST') throw new EvidenceAssuranceReceiptIntegrityError('A conflicting delivery receipt already exists.', { receiptId });
      throw new EvidenceAssuranceReceiptStoreError('The delivery receipt could not be committed.', { receiptId, created, committed }, error);
    }
  }
  function tenantRoot(tenant) { const path = resolve(root, sha256(`tenant:${tenant}`)); mkdirSync(path, { recursive: true, mode: 0o700 }); return path; }
  function indexPath(tenant) { return resolve(tenantRoot(tenant), 'index.encrypted.json'); }
  function receiptPath(tenant, receiptId) { return resolve(tenantRoot(tenant), 'receipts', `${receiptId}.receipt`); }
  function receiptNames(tenant) { const path = resolve(tenantRoot(tenant), 'receipts'); if (!existsSync(path)) return []; return readdirSync(path).filter((name) => name.endsWith('.receipt') && RECEIPT_ID.test(name.slice(0, -8))).sort(); }

  return Object.freeze({
    mode: selectedMode, enabled: true, required: isRequired,
    verifyAndRecord, get, list, verifyTenant, tenantStatus, health
  });
}

export function createEvidenceAssuranceReceiptStoreFromEnvironment({ env = process.env } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_MODE) ?? 'disabled';
  const required = parseBoolean(envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_REQUIRED) ?? false);
  if (mode === 'disabled') return createEvidenceAssuranceReceiptStore({ mode, required });
  const keysRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_KEYS);
  const primaryKeyId = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_PRIMARY_KEY_ID);
  const recipientsRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENTS);
  if (!keysRaw || !primaryKeyId) throw new EvidenceAssuranceReceiptStoreError('Dedicated assurance receipt encryption keys are required.', { reason: 'missing_receipt_keys' });
  if (!recipientsRaw) throw new EvidenceAssuranceReceiptStoreError('Assurance recipients are required for receipt verification.', { reason: 'missing_recipients' });
  try {
    return createEvidenceAssuranceReceiptStore({
      mode, required,
      directory: envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_DIR),
      encryptionKeys: JSON.parse(keysRaw),
      encryptionPrimaryKeyId: primaryKeyId,
      recipients: JSON.parse(recipientsRaw),
      maximumRecords: envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_MAX_RECORDS) ?? 100_000,
      clockSkewSeconds: envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECEIPT_CLOCK_SKEW_SECONDS) ?? 300
    });
  } catch (error) {
    if (error instanceof EvidenceAssuranceReceiptStoreError) throw error;
    throw new EvidenceAssuranceReceiptStoreError('Assurance receipt configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function parseReceiptRecipients(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Assurance recipients must be an object.');
  const result = new Map();
  for (const [recipientId, value] of Object.entries(raw)) {
    identifier(recipientId, 'recipientId');
    const entries = Object.entries(value?.receiptKeys ?? {});
    if (!entries.length) continue;
    const keys = new Map(entries.map(([keyId, configuration]) => {
      keyIdentifier(keyId);
      if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) throw new TypeError(`Receipt key ${recipientId}/${keyId} must be an object.`);
      const algorithm = String(configuration.algorithm ?? '').toLowerCase();
      if (!['ed25519', 'rsa-pss-sha256'].includes(algorithm)) throw new TypeError(`Receipt key ${recipientId}/${keyId} uses an unsupported algorithm.`);
      const publicKey = createPublicKey(String(configuration.publicKeyPem ?? ''));
      if (algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Receipt key ${recipientId}/${keyId} must be Ed25519.`);
      if (algorithm === 'rsa-pss-sha256' && !['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) throw new TypeError(`Receipt key ${recipientId}/${keyId} must be RSA.`);
      if (algorithm === 'rsa-pss-sha256' && (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Receipt key ${recipientId}/${keyId} must be at least 2048 bits.`);
      const canonical = publicKey.export({ type: 'spki', format: 'pem' }).toString();
      return [keyId, { algorithm, publicKey, fingerprint: sha256(canonical) }];
    }));
    result.set(recipientId, keys);
  }
  return result;
}
function validateInput(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid signed assurance delivery receipt is required.');
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    recipientId: identifier(input.recipientId, 'recipientId'),
    bundleId: bundleIdentifier(input.bundleId),
    packageSha256: hashValue(input.packageSha256, 'packageSha256'),
    claimedAt: isoDate(input.claimedAt, 'claimedAt'),
    receivedAt: isoDate(input.receivedAt, 'receivedAt'),
    keyId: keyIdentifier(input.keyId),
    signature: cleanText(input.signature, 'signature', 16, 4096)
  };
}
function receiptCanonical(value) { return [RECEIPT_FORMAT, value.recipientId, value.bundleId, value.packageSha256, value.receivedAt, value.keyId].join('\n'); }
function signatureBytes(value) { try { return strictBase64(value, 'delivery receipt signature'); } catch { throw new EvidenceAssuranceReceiptSignatureError(undefined, { reason: 'signature_encoding' }); } }
function assertSameReceipt(record, source) { if (record.recipientId !== source.recipientId || record.bundleId !== source.bundleId || record.packageSha256 !== source.packageSha256 || record.receivedAt !== source.receivedAt || record.keyId !== source.keyId || record.signature !== source.signature) throw new EvidenceAssuranceReceiptIntegrityError('A conflicting delivery receipt already exists.', { bundleId: source.bundleId }); }
function publicReceipt(record) { return { receiptId: record.receiptId, recipientId: record.recipientId, bundleId: record.bundleId, packageSha256: record.packageSha256, receivedAt: record.receivedAt, acknowledgedAt: record.acknowledgedAt, keyId: record.keyId, algorithm: record.algorithm, publicKeyFingerprint: record.publicKeyFingerprint, signature: record.signature, sequence: record.sequence, previousHash: record.previousHash, recordHash: record.recordHash }; }
function fsyncDirectory(path) { const descriptor = openSync(path, 'r'); try { fsyncSync(descriptor); } finally { closeSync(descriptor); } }
function recordAad(tenant, receiptId) { return `basitclaw:assurance-receipt:record:${tenant}:${receiptId}`; }
function indexAad(tenant) { return `basitclaw:assurance-receipt:index:${tenant}`; }
function bundleIdentifier(value) { const text = String(value ?? ''); if (!BUNDLE_ID.test(text)) throw new EvidenceValidationError('bundleId is invalid.', { field: 'bundleId' }); return text; }
function receiptIdentifier(value) { const text = String(value ?? ''); if (!RECEIPT_ID.test(text)) throw new EvidenceValidationError('receiptId is invalid.', { field: 'receiptId' }); return text; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function keyIdentifier(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(text)) throw new EvidenceValidationError('keyId is invalid.', { field: 'keyId' }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be true or false.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, required: false, mode: 'disabled' });
  return Object.freeze({ mode: 'disabled', enabled: false, required: false,
    verifyAndRecord() { throw new EvidenceConflictError('Assurance delivery receipts are disabled.'); },
    get() { return null; }, list() { return []; },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedReceipts: 0, chainHead: null }; },
    tenantStatus() { return status; }, health() { return status; }
  });
}
