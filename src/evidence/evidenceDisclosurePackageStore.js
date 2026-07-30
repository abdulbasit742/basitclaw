import {
  constants,
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID,
  sign as signAsymmetric,
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
  tenantEvidenceDirectory
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const INDEX_FORMAT = 'basitclaw-evidence-disclosure-receipt-index';
const RECEIPT_FORMAT = 'basitclaw-evidence-disclosure-receipt';
const PACKAGE_FORMAT = 'basitclaw-evidence-disclosure-package';
const SEALED_CONTENT_FORMAT = 'basitclaw-evidence-disclosure-sealed-content';
const PACKAGE_ID = /^DSP-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'shared-file']);

export class EvidenceDisclosureStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence disclosure store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureStoreError';
    this.code = 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE';
  }
}

export class EvidenceDisclosureIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence disclosure integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureIntegrityError';
    this.code = 'EVIDENCE_DISCLOSURE_INTEGRITY_FAILED';
  }
}

export function createEvidenceDisclosurePackageStore({
  mode = 'disabled',
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  signingKeys,
  signingPrimaryKeyId,
  recipients = {},
  maxPackageBytes = 25_000_000,
  maxRecords = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence disclosure directory is required.');

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const signing = parseSigningKeys(signingKeys, signingPrimaryKeyId);
  const recipientKeys = parseRecipients(recipients);
  const packageLimit = integer(maxPackageBytes, 'maxPackageBytes', 1_000_000, 100_000_000);
  const recordLimit = integer(maxRecords, 'maxRecords', 100, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function issue(input) {
    const request = validateIssue(input, packageLimit);
    const signer = signing.keys.get(signing.primaryKeyId);
    const recipient = request.includeContent
      ? recipientFor(request.recipientId)
      : null;
    const packageId = `DSP-${randomUUID().replaceAll('-', '')}`;
    const generatedAt = now().toISOString();
    const sealedContents = recipient
      ? request.contents.map((entry) => sealContent({ packageId, tenantId: request.tenantId, evidenceId: request.evidenceId, entry, recipient }))
      : [];
    const unsigned = {
      format: PACKAGE_FORMAT,
      version: 1,
      packageId,
      generatedAt,
      tenantId: request.tenantId,
      evidenceId: request.evidenceId,
      purpose: request.purpose,
      disclosure: {
        includeContent: request.includeContent,
        recipientId: recipient?.recipientId ?? null,
        recipientKeyId: recipient?.keyId ?? null,
        recipientKeyFingerprint: recipient?.fingerprint ?? null
      },
      manifest: request.manifest,
      sealedContents,
      signing: {
        algorithm: 'ed25519',
        keyId: signing.primaryKeyId,
        publicKeyFingerprint: signer.fingerprint
      }
    };
    const signature = signAsymmetric(null, Buffer.from(stableStringify(unsigned)), signer.privateKey).toString('base64');
    const disclosurePackage = { ...unsigned, signature };
    const packageSha256 = sha256(stableStringify(disclosurePackage));
    const manifestSha256 = sha256(stableStringify(request.manifest));

    return lock.withLock(`evidence-disclosures:${request.tenantId}`, () => {
      const index = loadIndex(request.tenantId);
      if (index.receipts.length >= recordLimit) {
        throw new EvidenceDisclosureStoreError('The evidence disclosure receipt store has reached capacity.', {
          reason: 'record_capacity', maxRecords: recordLimit
        });
      }
      const receipt = {
        format: RECEIPT_FORMAT,
        version: 1,
        packageId,
        tenantId: request.tenantId,
        evidenceId: request.evidenceId,
        evidenceVersions: request.versions,
        generatedAt,
        generatedBy: request.actor,
        purpose: request.purpose,
        includeContent: request.includeContent,
        recipientId: recipient?.recipientId ?? null,
        recipientKeyId: recipient?.keyId ?? null,
        recipientKeyFingerprint: recipient?.fingerprint ?? null,
        signingKeyId: signing.primaryKeyId,
        signingKeyFingerprint: signer.fingerprint,
        manifestSha256,
        packageSha256,
        sequence: index.sequence + 1,
        previousHash: index.headHash
      };
      receipt.hash = receiptHash(receipt);
      index.receipts.push(receipt);
      index.sequence = receipt.sequence;
      index.headHash = receipt.hash;
      index.updatedAt = generatedAt;
      saveIndex(request.tenantId, index);
      return {
        package: disclosurePackage,
        receipt: publicReceipt(receipt)
      };
    });
  }

  function list(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    let rows = loadSafe(tenant).receipts;
    if (evidence) rows = rows.filter((receipt) => receipt.evidenceId === evidence);
    return rows.slice(-integer(limit, 'limit', 1, 5000)).reverse().map(publicReceipt);
  }

  function verifyReceipt(tenantId, packageId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = packageIdentifier(packageId);
    const index = loadSafe(tenant);
    const receipt = index.receipts.find((entry) => entry.packageId === id);
    if (!receipt) throw new EvidenceConflictError('The evidence disclosure receipt was not found.', { packageId: id });
    if (receipt.hash !== receiptHash(receipt)) {
      throw new EvidenceDisclosureIntegrityError('The evidence disclosure receipt hash is invalid.', { packageId: id });
    }
    return { valid: true, receipt: publicReceipt(receipt), headSequence: index.sequence, headHash: index.headHash };
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const index = loadSafe(tenant);
    return {
      valid: true,
      tenantId: tenant,
      checkedReceipts: index.receipts.length,
      headSequence: index.sequence,
      headHash: index.headHash
    };
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const index = loadSafe(tenant);
      return {
        status: 'ready',
        enabled: true,
        receipts: index.receipts.length,
        contentPackages: index.receipts.filter((entry) => entry.includeContent).length,
        metadataOnlyPackages: index.receipts.filter((entry) => !entry.includeContent).length,
        configuredRecipients: recipientKeys.size,
        headSequence: index.sequence,
        headHash: index.headHash
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'evidence_disclosure_store_unavailable' };
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
        mode: 'shared-file-encrypted-disclosure-receipts',
        encryptedReceipts: true,
        signedPackages: true,
        contentSealing: 'rsa-oaep-sha256+aes-256-gcm',
        metadataOnlyByDefault: true,
        configuredRecipients: recipientKeys.size,
        signingKeyId: signing.primaryKeyId,
        signingKeyFingerprint: signing.keys.get(signing.primaryKeyId).fingerprint,
        maxPackageBytes: packageLimit,
        maxRecords: recordLimit,
        tenantDirectoryCount,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'shared-file-encrypted-disclosure-receipts', error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function recipientFor(recipientId) {
    const id = identifier(recipientId, 'recipientId');
    const recipient = recipientKeys.get(id);
    if (!recipient) throw new EvidenceValidationError('recipientId is not an approved disclosure recipient.', { field: 'recipientId' });
    const key = recipient.keys.get(recipient.primaryKeyId);
    return { recipientId: id, keyId: recipient.primaryKeyId, ...key };
  }

  function loadSafe(tenant) {
    try { return loadIndex(tenant); }
    catch (error) {
      if (error instanceof EvidenceDisclosureStoreError || error instanceof EvidenceDisclosureIntegrityError) throw error;
      throw new EvidenceDisclosureStoreError('The evidence disclosure receipt index could not be loaded.', {}, error);
    }
  }

  function loadIndex(tenant) {
    const path = indexPath(tenant);
    if (!existsSync(path)) return emptyIndex(tenant, now());
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceDisclosureStoreError('The evidence disclosure receipt index is unreadable.', {}, error); }
    const index = decryptEvidenceJson(envelope, encryption, indexAad(tenant), EvidenceDisclosureIntegrityError);
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.receipts)) {
      throw new EvidenceDisclosureIntegrityError('The evidence disclosure receipt index identity is invalid.');
    }
    verifyChain(index);
    return index;
  }

  function saveIndex(tenant, index) {
    atomicWriteEvidenceJson(indexPath(tenant), encryptEvidenceJson(index, encryption, indexAad(tenant)));
  }

  function indexPath(tenant) {
    return resolve(tenantEvidenceDirectory(root, tenant), 'disclosure-receipts.evidence');
  }

  return Object.freeze({
    enabled: true,
    mode: selectedMode,
    directory: root,
    maxPackageBytes: packageLimit,
    issue,
    list,
    verifyReceipt,
    verifyTenant,
    tenantStatus,
    health
  });
}

export function createEvidenceDisclosurePackageStoreFromEnvironment({ env = process.env } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE) ?? 'disabled';
  if (mode === 'disabled') return createEvidenceDisclosurePackageStore({ mode });
  const rawKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS);
  const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID);
  const rawSigningKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_SIGNING_KEYS);
  const primarySigningKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_SIGNING_KEY_ID);
  if (!rawKeys || !primaryKeyId || !rawSigningKeys || !primarySigningKeyId) {
    throw new EvidenceDisclosureStoreError('Dedicated disclosure encryption and signing keys are required.', {
      reason: 'missing_disclosure_configuration'
    });
  }
  try {
    return createEvidenceDisclosurePackageStore({
      mode,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR)
        ?? '.runtime-data/workforce-audit-evidence-disclosures',
      encryptionKeys: JSON.parse(rawKeys),
      encryptionPrimaryKeyId: primaryKeyId,
      signingKeys: JSON.parse(rawSigningKeys),
      signingPrimaryKeyId: primarySigningKeyId,
      recipients: JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS) ?? '{}'),
      maxPackageBytes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_PACKAGE_BYTES) ?? 25_000_000,
      maxRecords: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_RECORDS) ?? 100_000
    });
  } catch (error) {
    if (error instanceof EvidenceDisclosureStoreError) throw error;
    throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

export function verifyEvidenceDisclosurePackage(disclosurePackage, publicKeyPem) {
  if (!disclosurePackage || typeof disclosurePackage !== 'object' || Array.isArray(disclosurePackage)) {
    throw new EvidenceDisclosureIntegrityError('A disclosure package object is required.');
  }
  const { signature, ...unsigned } = disclosurePackage;
  if (unsigned.format !== PACKAGE_FORMAT || unsigned.version !== 1 || !PACKAGE_ID.test(unsigned.packageId ?? '')) {
    throw new EvidenceDisclosureIntegrityError('The disclosure package identity is invalid.');
  }
  let publicKey;
  try { publicKey = createPublicKey(String(publicKeyPem ?? '')); }
  catch (error) { throw new EvidenceDisclosureIntegrityError('The disclosure signing public key is invalid.', {}, error); }
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new EvidenceDisclosureIntegrityError('The disclosure signing key must be Ed25519.');
  const fingerprint = keyFingerprint(publicKey);
  if (unsigned.signing?.algorithm !== 'ed25519' || unsigned.signing?.publicKeyFingerprint !== fingerprint) {
    throw new EvidenceDisclosureIntegrityError('The disclosure package signing identity does not match the trusted public key.');
  }
  let signatureBytes;
  try { signatureBytes = Buffer.from(String(signature ?? ''), 'base64'); }
  catch (error) { throw new EvidenceDisclosureIntegrityError('The disclosure package signature is malformed.', {}, error); }
  if (!verifyAsymmetric(null, Buffer.from(stableStringify(unsigned)), publicKey, signatureBytes)) {
    throw new EvidenceDisclosureIntegrityError('The disclosure package signature verification failed.');
  }
  return {
    valid: true,
    packageId: unsigned.packageId,
    packageSha256: sha256(stableStringify(disclosurePackage)),
    manifestSha256: sha256(stableStringify(unsigned.manifest)),
    signingKeyFingerprint: fingerprint,
    sealedContentCount: Array.isArray(unsigned.sealedContents) ? unsigned.sealedContents.length : 0
  };
}

function sealContent({ packageId, tenantId, evidenceId, entry, recipient }) {
  const content = validateContent(entry);
  const payload = Buffer.from(JSON.stringify({
    format: SEALED_CONTENT_FORMAT,
    version: 1,
    packageId,
    tenantId,
    evidenceId,
    evidenceVersion: content.version,
    filename: content.filename,
    mediaType: content.mediaType,
    contentSha256: content.sha256,
    sizeBytes: content.sizeBytes,
    contentBase64: content.content.toString('base64')
  }));
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from(`basitclaw:evidence-disclosure:${packageId}:${recipient.recipientId}:${recipient.keyId}:${content.version}`);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const wrappedKey = publicEncrypt({
    key: recipient.publicKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, key);
  return {
    format: SEALED_CONTENT_FORMAT,
    version: 1,
    algorithm: 'rsa-oaep-sha256+aes-256-gcm',
    evidenceVersion: content.version,
    contentSha256: content.sha256,
    sizeBytes: content.sizeBytes,
    recipientId: recipient.recipientId,
    recipientKeyId: recipient.keyId,
    recipientKeyFingerprint: recipient.fingerprint,
    aad: aad.toString('base64'),
    wrappedKey: wrappedKey.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    ciphertextSha256: sha256(ciphertext)
  };
}

function validateIssue(input, maxPackageBytes) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A disclosure package request is required.');
  const contents = Array.isArray(input.contents) ? input.contents.map(validateContent) : [];
  const includeContent = Boolean(input.includeContent);
  if (includeContent && !contents.length) throw new EvidenceValidationError('Content-inclusive disclosure packages require selected evidence content.', { field: 'contents' });
  if (!includeContent && contents.length) throw new EvidenceValidationError('Metadata-only disclosure packages cannot contain evidence bytes.', { field: 'contents' });
  const totalBytes = contents.reduce((sum, entry) => sum + entry.sizeBytes, 0);
  if (totalBytes > maxPackageBytes) throw new EvidenceValidationError('The selected evidence content exceeds the disclosure package byte limit.', { maxPackageBytes, totalBytes });
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    evidenceId: evidenceIdentifier(input.evidenceId),
    versions: uniqueVersions(input.versions),
    actor: identifier(input.actor, 'actor'),
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    includeContent,
    recipientId: includeContent ? identifier(input.recipientId, 'recipientId') : null,
    manifest: validateManifest(input.manifest),
    contents
  };
}

function validateManifest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new EvidenceValidationError('A disclosure manifest is required.', { field: 'manifest' });
  const bytes = Buffer.byteLength(stableStringify(value));
  if (bytes > 5_000_000) throw new EvidenceValidationError('The disclosure manifest is too large.', { field: 'manifest' });
  return structuredClone(value);
}

function validateContent(value) {
  if (!value || typeof value !== 'object' || !Buffer.isBuffer(value.content)) throw new EvidenceValidationError('Disclosure content must contain a Buffer.', { field: 'contents' });
  const version = integer(value.version, 'version', 1, 1_000_000);
  const sizeBytes = integer(value.sizeBytes, 'sizeBytes', 0, 100_000_000);
  const digest = hashValue(value.sha256, 'sha256');
  if (value.content.length !== sizeBytes || sha256(value.content) !== digest) {
    throw new EvidenceDisclosureIntegrityError('Disclosure content does not match its immutable metadata.', { version });
  }
  return {
    version,
    filename: cleanText(value.filename, 'filename', 1, 255),
    mediaType: cleanText(value.mediaType, 'mediaType', 1, 255),
    sha256: digest,
    sizeBytes,
    content: Buffer.from(value.content)
  };
}

function parseSigningKeys(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure signing keys must be an object.');
  const keys = new Map();
  for (const [keyId, pem] of Object.entries(raw)) {
    identifier(keyId, 'signingKeyId');
    const privateKey = createPrivateKey(String(pem));
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Disclosure signing key ${keyId} must be Ed25519.`);
    const publicKey = createPublicKey(privateKey);
    keys.set(keyId, { privateKey, publicKey, fingerprint: keyFingerprint(publicKey) });
  }
  if (!keys.size || keys.size > 20) throw new TypeError('Disclosure signing keys must contain 1 to 20 entries.');
  const primary = identifier(primaryKeyId, 'signingPrimaryKeyId');
  if (!keys.has(primary)) throw new TypeError('The disclosure primary signing key ID is not present in the signing keyring.');
  return Object.freeze({ keys, primaryKeyId: primary });
}

function parseRecipients(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure recipients must be an object.');
  const recipients = new Map();
  for (const [recipientId, config] of Object.entries(raw)) {
    identifier(recipientId, 'recipientId');
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Disclosure recipient ${recipientId} must be an object.`);
    const keys = new Map();
    for (const [keyId, pem] of Object.entries(config.publicKeys ?? {})) {
      identifier(keyId, 'recipientKeyId');
      const publicKey = createPublicKey(String(pem));
      if (publicKey.asymmetricKeyType !== 'rsa' || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
        throw new TypeError(`Disclosure recipient key ${recipientId}/${keyId} must be RSA with at least 2048 bits.`);
      }
      keys.set(keyId, { publicKey, fingerprint: keyFingerprint(publicKey) });
    }
    if (!keys.size) throw new TypeError(`Disclosure recipient ${recipientId} must contain at least one public key.`);
    const primaryKeyId = identifier(config.primaryKeyId ?? [...keys.keys()][0], 'recipientPrimaryKeyId');
    if (!keys.has(primaryKeyId)) throw new TypeError(`Disclosure recipient ${recipientId} primary key is not configured.`);
    recipients.set(recipientId, { primaryKeyId, keys });
  }
  if (recipients.size > 100) throw new TypeError('Disclosure recipients cannot exceed 100 entries.');
  return recipients;
}

function verifyChain(index) {
  let previousHash = null;
  let expectedSequence = 1;
  for (const receipt of index.receipts) {
    if (receipt.sequence !== expectedSequence || receipt.previousHash !== previousHash || receipt.hash !== receiptHash(receipt)) {
      throw new EvidenceDisclosureIntegrityError('The evidence disclosure receipt chain is invalid.', { packageId: receipt.packageId, expectedSequence });
    }
    previousHash = receipt.hash;
    expectedSequence += 1;
  }
  if (index.sequence !== expectedSequence - 1 || index.headHash !== previousHash) {
    throw new EvidenceDisclosureIntegrityError('The evidence disclosure receipt chain head is inconsistent.');
  }
}

function receiptHash(receipt) { const { hash, ...body } = receipt; return sha256(stableStringify(body)); }
function emptyIndex(tenantId, date) { const at = date.toISOString(); return { format: INDEX_FORMAT, version: 1, tenantId, createdAt: at, updatedAt: at, sequence: 0, headHash: null, receipts: [] }; }
function indexAad(tenantId) { return `basitclaw:evidence-disclosure-receipts:${tenantId}`; }
function keyFingerprint(key) { return sha256(key.export({ type: 'spki', format: 'der' })); }
function publicReceipt(receipt) { const { format, version, tenantId, ...publicFields } = receipt; return structuredClone(publicFields); }
function packageIdentifier(value) { const id = String(value ?? ''); if (!PACKAGE_ID.test(id)) throw new EvidenceValidationError('packageId is invalid.', { field: 'packageId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function uniqueVersions(value) { if (!Array.isArray(value) || !value.length || value.length > 100) throw new EvidenceValidationError('versions must contain 1 to 100 version numbers.', { field: 'versions' }); return [...new Set(value.map((entry) => integer(entry, 'version', 1, 1_000_000)))].sort((a, b) => a - b); }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled' });
  return Object.freeze({
    enabled: false,
    mode: 'disabled',
    maxPackageBytes: 0,
    issue() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    list() { return []; },
    verifyReceipt() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedReceipts: 0, headSequence: 0, headHash: null }; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}
