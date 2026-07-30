import {
  constants,
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  sign,
  verify
} from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
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
  sha256
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const PACKAGE_FORMAT = 'basitclaw-evidence-disclosure-v1';
const INDEX_FORMAT = 'basitclaw-evidence-disclosure-index';
const PACKAGE_ID = /^DSP-[a-f0-9]{32}$/;
const MODES = new Set(['disabled', 'shared-file']);

export class EvidenceDisclosureStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence disclosure store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureStoreError';
    this.code = 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE';
  }
}
export class EvidenceDisclosureIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Evidence disclosure package integrity verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceDisclosureIntegrityError';
    this.code = 'EVIDENCE_DISCLOSURE_INTEGRITY_FAILED';
  }
}
export class EvidenceDisclosureExpiredError extends EvidenceConflictError {
  constructor(packageId, expiresAt) {
    super('The evidence disclosure package has expired.', { packageId, expiresAt });
    this.name = 'EvidenceDisclosureExpiredError';
    this.code = 'EVIDENCE_DISCLOSURE_EXPIRED';
  }
}
export class EvidenceDisclosureRevokedError extends EvidenceConflictError {
  constructor(packageId, revokedAt) {
    super('The evidence disclosure package has been revoked.', { packageId, revokedAt });
    this.name = 'EvidenceDisclosureRevokedError';
    this.code = 'EVIDENCE_DISCLOSURE_REVOKED';
  }
}
export class EvidenceDisclosureLimitError extends EvidenceConflictError {
  constructor(packageId, maximumDownloads) {
    super('The evidence disclosure package download limit has been reached.', { packageId, maximumDownloads });
    this.name = 'EvidenceDisclosureLimitError';
    this.code = 'EVIDENCE_DISCLOSURE_DOWNLOAD_LIMIT';
  }
}

export function createEvidenceDisclosureStore({
  mode = 'disabled',
  directory,
  metadataKeys,
  metadataPrimaryKeyId,
  signingPrivateKeys,
  signingPrimaryKeyId,
  maximumPackageBytes = 100_000_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence disclosure directory is required.');

  const root = resolve(String(directory));
  const metadataKeyring = parseEvidenceKeyring(metadataKeys, metadataPrimaryKeyId);
  const signing = parseSigningKeys(signingPrivateKeys, signingPrimaryKeyId);
  const maximumBytes = integer(maximumPackageBytes, 'maximumPackageBytes', 1024, 1_000_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function create(input, { actor } = {}) {
    const request = validateCreateInput(input, maximumBytes, now);
    const createdBy = identifier(actor, 'actor');
    const recipient = parseRecipient(request.recipientPublicKeyPem);
    const payloadBytes = Buffer.from(stableStringify(request.payload), 'utf8');
    const payloadSha256 = sha256(payloadBytes);
    const packageId = disclosureId({
      tenantId: request.tenantId,
      payloadSha256,
      recipientFingerprint: recipient.fingerprint,
      expiresAt: request.expiresAt,
      maximumDownloads: request.maximumDownloads,
      purpose: request.purpose
    });

    return lock.withLock(`evidence-disclosure:${request.tenantId}`, () => {
      const index = loadIndex(request.tenantId);
      const existing = index.packages.find((entry) => entry.packageId === packageId);
      if (existing) {
        verifyLocked(request.tenantId, packageId, index);
        return { created: false, duplicate: true, disclosure: publicMetadata(existing) };
      }
      const path = packageFile(request.tenantId, packageId);
      if (existsSync(path)) throw new EvidenceDisclosureIntegrityError('A package exists without encrypted lifecycle metadata.', { packageId });

      const disclosurePackage = sealPackage({
        packageId,
        request,
        recipient,
        payloadBytes,
        payloadSha256,
        signing,
        createdAt: now().toISOString()
      });
      writeJsonExclusive(path, disclosurePackage, packageId);
      const entry = {
        packageId,
        createdAt: disclosurePackage.createdAt,
        createdBy,
        expiresAt: request.expiresAt,
        maximumDownloads: request.maximumDownloads,
        downloadCount: 0,
        lastDownloadedAt: null,
        recipientKeyId: request.recipientKeyId,
        recipientKeyFingerprint: recipient.fingerprint,
        signingKeyId: disclosurePackage.signingKeyId,
        signingPublicKeyFingerprint: disclosurePackage.signingPublicKeyFingerprint,
        payloadSha256,
        payloadSizeBytes: payloadBytes.length,
        packageSha256: sha256(Buffer.from(stableStringify(disclosurePackage))),
        purpose: request.purpose,
        itemCount: request.itemCount,
        revokedAt: null,
        revokedBy: null,
        revocationReason: null
      };
      index.packages.push(entry);
      try {
        saveIndex(request.tenantId, index);
      } catch (error) {
        try { rmSync(path, { force: true }); } catch {}
        throw error;
      }
      return { created: true, duplicate: false, disclosure: publicMetadata(entry) };
    });
  }

  function list(tenantId, { limit = 100 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const maximum = integer(limit, 'limit', 1, 1000);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => loadIndex(tenant).packages
      .slice().sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, maximum).map(publicMetadata));
  }
  function metadata(tenantId, packageId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = packageIdentifier(packageId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => publicMetadata(findMetadata(loadIndex(tenant), id)));
  }
  function download(tenantId, packageId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = packageIdentifier(packageId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const index = loadIndex(tenant);
      const entry = findMetadata(index, id);
      assertDeliverable(entry, now);
      const result = verifyLocked(tenant, id, index);
      entry.downloadCount += 1;
      entry.lastDownloadedAt = now().toISOString();
      saveIndex(tenant, index);
      return { disclosure: publicMetadata(entry), package: result.package };
    });
  }
  function verifyPackage(tenantId, packageId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = packageIdentifier(packageId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const result = verifyLocked(tenant, id, loadIndex(tenant));
      return { valid: true, disclosure: publicMetadata(result.metadata), package: packageSummary(result.package) };
    });
  }
  function revoke(tenantId, packageId, { actor, reason } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = packageIdentifier(packageId);
    const revokedBy = identifier(actor, 'actor');
    const revocationReason = cleanText(reason, 'reason', 10, 500);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const index = loadIndex(tenant);
      const entry = findMetadata(index, id);
      if (!entry.revokedAt) {
        entry.revokedAt = now().toISOString();
        entry.revokedBy = revokedBy;
        entry.revocationReason = revocationReason;
        saveIndex(tenant, index);
      }
      return publicMetadata(entry);
    });
  }
  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const entries = loadIndex(tenant).packages;
      const current = now();
      const counts = { active: 0, expired: 0, revoked: 0, exhausted: 0 };
      for (const entry of entries) {
        if (entry.revokedAt) counts.revoked += 1;
        else if (current >= new Date(entry.expiresAt)) counts.expired += 1;
        else if (entry.downloadCount >= entry.maximumDownloads) counts.exhausted += 1;
        else counts.active += 1;
      }
      return { status: 'ready', enabled: true, total: entries.length, ...counts };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }
  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const primary = signing.keys.get(signing.primaryKeyId);
      return {
        status: 'ready', enabled: true, mode: 'recipient-bound-encrypted-disclosures',
        encryptedMetadata: true, recipientEncryptedPackages: true, signedPackages: true,
        generalEvidenceDownload: false, maximumPackageBytes: maximumBytes,
        signingKeyId: signing.primaryKeyId, signingPublicKeyFingerprint: primary.fingerprint,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function verifyLocked(tenant, packageId, index) {
    const entry = findMetadata(index, packageId);
    const path = packageFile(tenant, packageId);
    if (!existsSync(path)) throw new EvidenceDisclosureIntegrityError('The disclosure package file is missing.', { packageId });
    let value;
    try { value = JSON.parse(readFileSync(path, 'utf8')); }
    catch (error) { throw new EvidenceDisclosureStoreError('The disclosure package cannot be read.', { packageId }, error); }
    if (!value || value.format !== PACKAGE_FORMAT || value.version !== 1 || value.packageId !== packageId) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package identity is invalid.', { packageId });
    }
    const configured = signing.keys.get(value.signingKeyId);
    if (!configured || configured.fingerprint !== value.signingPublicKeyFingerprint
        || configured.publicKeyPem !== value.signingPublicKeyPem) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package references an untrusted signing key.', { packageId });
    }
    const { signature, ...unsigned } = value;
    let signatureValid = false;
    try { signatureValid = verify(null, Buffer.from(stableStringify(unsigned)), configured.publicKey, Buffer.from(signature, 'base64')); }
    catch (error) { throw new EvidenceDisclosureIntegrityError('The disclosure package signature is malformed.', { packageId }, error); }
    if (!signatureValid) throw new EvidenceDisclosureIntegrityError('The disclosure package signature verification failed.', { packageId });
    const packageSha256 = sha256(Buffer.from(stableStringify(value)));
    if (packageSha256 !== entry.packageSha256 || value.payloadSha256 !== entry.payloadSha256
        || value.payloadSizeBytes !== entry.payloadSizeBytes
        || value.recipientKeyFingerprint !== entry.recipientKeyFingerprint
        || value.expiresAt !== entry.expiresAt || value.maximumDownloads !== entry.maximumDownloads) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package does not match encrypted lifecycle metadata.', { packageId });
    }
    return { metadata: entry, package: value };
  }
  function loadIndex(tenant) {
    const path = indexFile(tenant);
    if (!existsSync(path)) return { format: INDEX_FORMAT, version: 1, tenantId: tenant, packages: [] };
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceDisclosureStoreError('The encrypted disclosure index is unreadable.', {}, error); }
    const index = decryptEvidenceJson(envelope, metadataKeyring, indexAad(tenant), EvidenceDisclosureIntegrityError);
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.tenantId !== tenant || !Array.isArray(index.packages)) {
      throw new EvidenceDisclosureIntegrityError('The encrypted disclosure index has an invalid identity.');
    }
    return index;
  }
  function saveIndex(tenant, index) {
    try { atomicWriteEvidenceJson(indexFile(tenant), encryptEvidenceJson(index, metadataKeyring, indexAad(tenant))); }
    catch (error) { throw new EvidenceDisclosureStoreError('The encrypted disclosure index could not be committed.', {}, error); }
  }
  function tenantDirectory(tenant) {
    const path = resolve(root, sha256(tenant));
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return path;
  }
  function indexFile(tenant) { return resolve(tenantDirectory(tenant), 'index.encrypted.json'); }
  function packageFile(tenant, packageId) { return resolve(tenantDirectory(tenant), 'packages', `${packageId}.json`); }

  return Object.freeze({
    mode: selectedMode, enabled: true, directory: root,
    create, list, metadata, download, verify: verifyPackage, revoke, tenantStatus, health
  });
}

export function createEvidenceDisclosureStoreFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE) ?? 'disabled';
  if (mode === 'disabled') return createEvidenceDisclosureStore({ mode });
  if (!evidenceRegistry?.evidencePreservationEnabled || !evidenceRegistry?.evidenceTimeAttestationEnabled
      || !evidenceRegistry?.evidenceTimeAttestationGovernanceEnabled) {
    throw new EvidenceDisclosureStoreError('Evidence disclosures require preservation, time-attestation and governance controls.', {
      reason: 'missing_evidence_trust_dependencies'
    });
  }
  const rawKeys = envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS);
  const primaryKeyId = envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_KEY_ID);
  const rawSigning = envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_SIGNING_PRIVATE_KEYS);
  const primarySigningKeyId = envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_PRIMARY_SIGNING_KEY_ID);
  if (!rawKeys || !primaryKeyId) throw new EvidenceDisclosureStoreError('Dedicated disclosure metadata keys are required.', { reason: 'missing_disclosure_metadata_keys' });
  if (!rawSigning || !primarySigningKeyId) throw new EvidenceDisclosureStoreError('Dedicated disclosure signing keys are required.', { reason: 'missing_disclosure_signing_keys' });
  try {
    return createEvidenceDisclosureStore({
      mode,
      directory: envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_DIR),
      metadataKeys: JSON.parse(rawKeys),
      metadataPrimaryKeyId: primaryKeyId,
      signingPrivateKeys: JSON.parse(rawSigning),
      signingPrimaryKeyId: primarySigningKeyId,
      maximumPackageBytes: Number(envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MAX_PACKAGE_BYTES) ?? 100_000_000)
    });
  } catch (error) {
    if (error instanceof EvidenceDisclosureStoreError) throw error;
    throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is invalid.', { reason: error?.code ?? 'invalid_disclosure_configuration' }, error);
  }
}

function sealPackage({ packageId, request, recipient, payloadBytes, payloadSha256, signing, createdAt }) {
  const dataKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
  cipher.setAAD(Buffer.from(`${PACKAGE_FORMAT}:${packageId}:${recipient.fingerprint}`));
  const ciphertext = Buffer.concat([cipher.update(payloadBytes), cipher.final()]);
  const wrappedKey = publicEncrypt({ key: recipient.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, dataKey);
  const keyId = signing.primaryKeyId;
  const signer = signing.keys.get(keyId);
  const unsigned = {
    format: PACKAGE_FORMAT, version: 1, packageId, createdAt,
    expiresAt: request.expiresAt, maximumDownloads: request.maximumDownloads,
    recipientKeyId: request.recipientKeyId, recipientKeyFingerprint: recipient.fingerprint,
    keyWrapAlgorithm: 'rsa-oaep-sha256', contentEncryptionAlgorithm: 'aes-256-gcm',
    signingAlgorithm: 'ed25519', signingKeyId: keyId,
    signingPublicKeyPem: signer.publicKeyPem, signingPublicKeyFingerprint: signer.fingerprint,
    payloadSha256, payloadSizeBytes: payloadBytes.length,
    wrappedKey: wrappedKey.toString('base64'), iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64')
  };
  return { ...unsigned, signature: sign(null, Buffer.from(stableStringify(unsigned)), signer.privateKey).toString('base64') };
}
function validateCreateInput(input, maximumBytes, now) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid evidence disclosure package is required.');
  const expiresAt = isoDate(input.expiresAt, 'expiresAt');
  if (new Date(expiresAt) <= now()) throw new EvidenceValidationError('expiresAt must be in the future.', { field: 'expiresAt' });
  if (!input.payload || typeof input.payload !== 'object' || Array.isArray(input.payload)) throw new EvidenceValidationError('payload must be an object.', { field: 'payload' });
  if (Buffer.byteLength(stableStringify(input.payload)) > maximumBytes) throw new EvidenceValidationError('payload exceeds the configured package limit.', { field: 'payload' });
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    recipientKeyId: identifier(input.recipientKeyId, 'recipientKeyId'),
    recipientPublicKeyPem: cleanText(input.recipientPublicKeyPem, 'recipientPublicKeyPem', 100, 20_000),
    expiresAt,
    maximumDownloads: integer(input.maximumDownloads, 'maximumDownloads', 1, 1000),
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    itemCount: integer(input.itemCount, 'itemCount', 1, 1000),
    payload: input.payload
  };
}
function parseRecipient(pem) {
  try {
    const publicKey = createPublicKey(pem);
    if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType) || (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new Error('recipient_key_invalid');
    const canonical = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    return { publicKey, fingerprint: sha256(canonical) };
  } catch (error) {
    throw new EvidenceValidationError('recipientPublicKeyPem must contain an RSA public key of at least 2048 bits.', { field: 'recipientPublicKeyPem', reason: error.message });
  }
}
function parseSigningKeys(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure signing private keys must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 20) throw new TypeError('Disclosure signing private keys must contain 1 to 20 entries.');
  const keys = new Map(entries.map(([keyId, pem]) => {
    identifier(keyId, 'signingKeyId');
    const privateKey = createPrivateKey(String(pem));
    if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Disclosure signing key ${keyId} must be Ed25519.`);
    const publicKey = createPublicKey(privateKey);
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    return [keyId, { privateKey, publicKey, publicKeyPem, fingerprint: sha256(publicKeyPem) }];
  }));
  if (!keys.has(String(primaryKeyId ?? ''))) throw new TypeError('The disclosure primary signing key ID is not present in the keyring.');
  return Object.freeze({ keys, primaryKeyId: String(primaryKeyId) });
}
function assertDeliverable(entry, now) {
  if (entry.revokedAt) throw new EvidenceDisclosureRevokedError(entry.packageId, entry.revokedAt);
  if (now() >= new Date(entry.expiresAt)) throw new EvidenceDisclosureExpiredError(entry.packageId, entry.expiresAt);
  if (entry.downloadCount >= entry.maximumDownloads) throw new EvidenceDisclosureLimitError(entry.packageId, entry.maximumDownloads);
}
function disclosureId(input) { return `DSP-${sha256(stableStringify(input)).slice(0, 32)}`; }
function findMetadata(index, packageId) { const entry = index.packages.find((candidate) => candidate.packageId === packageId); if (!entry) throw new EvidenceDisclosureIntegrityError('Disclosure metadata does not exist.', { packageId }); return entry; }
function publicMetadata(entry) { return { ...entry }; }
function packageSummary(value) { return { packageId: value.packageId, format: value.format, version: value.version, createdAt: value.createdAt, expiresAt: value.expiresAt, recipientKeyId: value.recipientKeyId, recipientKeyFingerprint: value.recipientKeyFingerprint, payloadSha256: value.payloadSha256, payloadSizeBytes: value.payloadSizeBytes, signingKeyId: value.signingKeyId, signingPublicKeyFingerprint: value.signingPublicKeyFingerprint }; }
function writeJsonExclusive(path, value, packageId) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor = null;
  let created = false;
  let committed = false;
  try {
    descriptor = openSync(path, 'wx', 0o600); created = true;
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8'); fsyncSync(descriptor);
    closeSync(descriptor); descriptor = null; committed = true;
    const directory = openSync(dirname(path), 'r'); try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    if (created && !committed) try { rmSync(path, { force: true }); } catch {}
    if (error?.code === 'EEXIST') throw new EvidenceDisclosureIntegrityError('A conflicting disclosure package already exists.', { packageId });
    throw new EvidenceDisclosureStoreError('The disclosure package could not be committed.', { packageId }, error);
  }
}
function packageIdentifier(value) { const id = String(value ?? ''); if (!PACKAGE_ID.test(id)) throw new EvidenceValidationError('packageId is invalid.', { field: 'packageId' }); return id; }
function indexAad(tenant) { return `basitclaw:evidence-disclosure:index:${tenant}`; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled' });
  return Object.freeze({ mode: 'disabled', enabled: false,
    create() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    list() { return []; }, metadata() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    download() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    verify() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    revoke() { throw new EvidenceConflictError('Evidence disclosure packages are disabled.'); },
    tenantStatus() { return status; }, health() { return status; }
  });
}
