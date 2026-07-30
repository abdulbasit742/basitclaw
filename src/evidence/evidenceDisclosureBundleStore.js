import {
  constants,
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  randomBytes,
  sign as signValue,
  publicEncrypt
} from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256
} from './evidenceCrypto.js';
import { EvidenceConflictError, EvidenceIntegrityError, EvidenceStoreError, EvidenceValidationError } from './evidenceRegistry.js';
import {
  disclosurePackageSignatureBody,
  disclosurePayload,
  packageAad,
  stableStringify,
  verifyDisclosurePackageSignature
} from './evidenceDisclosureVerifier.js';

const PACKAGE_FORMAT = 'basitclaw-assurance-disclosure-package-v1';
const RECORD_FORMAT = 'basitclaw-assurance-disclosure-record-v1';
const BUNDLE_ID = /^DSC-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
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

export function createEvidenceDisclosureBundleStore({
  mode = 'disabled',
  directory,
  indexKeys,
  indexPrimaryKeyId,
  recipients,
  signingKeys,
  signingPrimaryKeyId,
  defaultExpiryDays = 30,
  maximumPayloadBytes = 5_000_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledStore();
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence disclosure directory is required.');
  const root = resolve(String(directory));
  const index = parseEvidenceKeyring(indexKeys, indexPrimaryKeyId);
  const recipientKeyring = parseRecipients(recipients);
  const enterpriseSigning = parseSigningKeys(signingKeys, signingPrimaryKeyId);
  const expiryDays = integer(defaultExpiryDays, 'defaultExpiryDays', 1, 365);
  const payloadLimit = integer(maximumPayloadBytes, 'maximumPayloadBytes', 10_000, 25_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function create(input, context = {}) {
    const request = validateCreateInput(input, context);
    const recipient = recipientKeyring.get(request.recipientId);
    if (!recipient) {
      throw new EvidenceValidationError('recipientId is not configured for evidence disclosure.', {
        field: 'recipientId',
        recipientId: request.recipientId
      });
    }
    const createdAt = now();
    if (!(createdAt instanceof Date) || Number.isNaN(createdAt.getTime())) throw new TypeError('now must return a valid Date.');
    const expiresAt = request.expiresAt ?? new Date(createdAt.getTime() + expiryDays * 86_400_000);
    if (expiresAt <= createdAt) throw new EvidenceValidationError('expiresAt must be after bundle creation.', { field: 'expiresAt' });
    if (expiresAt.getTime() - createdAt.getTime() > 365 * 86_400_000) throw new EvidenceValidationError('expiresAt cannot exceed one year.', { field: 'expiresAt' });

    const bundleId = `DSC-${sha256([
      request.tenantId,
      request.evidenceId,
      request.recipientId,
      request.idempotencyKey
    ].join('|')).slice(0, 32)}`;
    const paths = bundlePaths(request.tenantId, bundleId);

    return lock.withLock(`evidence-disclosure:${request.tenantId}`, () => {
      if (existsSync(paths.package) || existsSync(paths.record)) {
        if (!existsSync(paths.package) || !existsSync(paths.record)) {
          throw new EvidenceDisclosureIntegrityError('A partial disclosure bundle already exists.', { bundleId });
        }
        const record = readRecord(paths.record, request.tenantId, bundleId);
        if (record.evidenceId !== request.evidenceId || record.recipientId !== request.recipientId
            || record.idempotencyKey !== request.idempotencyKey) {
          throw new EvidenceDisclosureIntegrityError('The idempotency key conflicts with an existing disclosure bundle.', { bundleId });
        }
        const verification = verifyLocked(request.tenantId, bundleId);
        return { created: false, duplicate: true, bundle: publicRecord(record), verification };
      }

      const signing = enterpriseSigning.keys.get(enterpriseSigning.primaryKeyId);
      const recipientKey = recipient.keys.get(recipient.primaryKeyId);
      const createdIso = createdAt.toISOString();
      const expiresIso = expiresAt.toISOString();
      const payload = disclosurePayload({
        bundleId,
        createdAt: createdIso,
        expiresAt: expiresIso,
        generatedBy: request.actor,
        purpose: request.purpose,
        policy: {
          rawEvidenceIncluded: false,
          metadataOnly: true,
          recipientRestricted: true,
          offlineVerificationSupported: true
        },
        ...request.payloadBody
      });
      const plaintext = Buffer.from(stableStringify(payload));
      if (plaintext.length > payloadLimit) {
        throw new EvidenceValidationError('The disclosure payload exceeds the configured maximum.', {
          maximumPayloadBytes: payloadLimit,
          actualBytes: plaintext.length
        });
      }

      const contentKey = randomBytes(32);
      const iv = randomBytes(12);
      const base = {
        format: PACKAGE_FORMAT,
        version: 1,
        bundleId,
        recipientKeyId: `${request.recipientId}:${recipient.primaryKeyId}`,
        wrappingAlgorithm: 'rsa-oaep-sha256',
        contentAlgorithm: 'aes-256-gcm',
        signingAlgorithm: signing.algorithm,
        signingKeyId: enterpriseSigning.primaryKeyId,
        createdAt: createdIso,
        expiresAt: expiresIso,
        payloadSha256: sha256(plaintext)
      };
      const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
      cipher.setAAD(Buffer.from(packageAad(base)));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const envelope = {
        ...base,
        ciphertextSha256: sha256(ciphertext),
        wrappedKey: publicEncrypt({
          key: recipientKey,
          oaepHash: 'sha256',
          padding: constants.RSA_PKCS1_OAEP_PADDING
        }, contentKey).toString('base64'),
        iv: iv.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
        ciphertext: ciphertext.toString('base64')
      };
      const signature = signEnvelope(envelope, signing);
      const packageValue = { ...envelope, signature: signature.toString('base64') };
      const record = {
        format: RECORD_FORMAT,
        version: 1,
        bundleId,
        tenantId: request.tenantId,
        evidenceId: request.evidenceId,
        recipientId: request.recipientId,
        recipientKeyId: recipient.primaryKeyId,
        signingKeyId: enterpriseSigning.primaryKeyId,
        idempotencyKey: request.idempotencyKey,
        createdAt: createdIso,
        expiresAt: expiresIso,
        purpose: request.purpose,
        actor: request.actor,
        manifestSha256: payload.manifestSha256,
        payloadSha256: envelope.payloadSha256,
        ciphertextSha256: envelope.ciphertextSha256,
        versionCount: Array.isArray(request.payloadBody?.evidence?.versions) ? request.payloadBody.evidence.versions.length : 0
      };

      writeJsonExclusive(paths.package, packageValue, bundleId);
      try {
        writeJsonExclusive(paths.record, encryptEvidenceJson(record, index, recordAad(request.tenantId, bundleId)), bundleId);
      } catch (error) {
        throw storeFailure(error, 'write_record', bundleId);
      }
      return {
        created: true,
        duplicate: false,
        bundle: publicRecord(record),
        verification: verifyLocked(request.tenantId, bundleId)
      };
    });
  }

  function list(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const requestedLimit = integer(limit, 'limit', 1, 5000);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      return recordNames(paths.records)
        .map((name) => readRecord(resolve(paths.records, name), tenant, name.slice(0, -7)))
        .filter((record) => !evidence || record.evidenceId === evidence)
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
        .slice(0, requestedLimit)
        .map(publicRecord);
    });
  }

  function packageFor(tenantId, bundleId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = bundleIdentifier(bundleId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      verifyLocked(tenant, id);
      return JSON.parse(readFileSync(bundlePaths(tenant, id).package, 'utf8'));
    });
  }

  function verify(tenantId, bundleId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = bundleIdentifier(bundleId);
    return lock.withLock(`evidence-disclosure:${tenant}`, () => verifyLocked(tenant, id));
  }

  function verifyLocked(tenant, bundleId) {
    const paths = bundlePaths(tenant, bundleId);
    if (!existsSync(paths.package) || !existsSync(paths.record)) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package or encrypted record is missing.', { bundleId });
    }
    let packageValue;
    try { packageValue = JSON.parse(readFileSync(paths.package, 'utf8')); }
    catch (error) { throw new EvidenceDisclosureStoreError('The disclosure package is unreadable.', { bundleId }, error); }
    const signature = verifyDisclosurePackageSignature(packageValue, enterpriseSigning.publicKeys);
    const record = readRecord(paths.record, tenant, bundleId);
    if (record.payloadSha256 !== packageValue.payloadSha256
        || record.ciphertextSha256 !== packageValue.ciphertextSha256
        || `${record.recipientId}:${record.recipientKeyId}` !== packageValue.recipientKeyId
        || record.signingKeyId !== packageValue.signingKeyId
        || record.createdAt !== packageValue.createdAt
        || record.expiresAt !== packageValue.expiresAt) {
      throw new EvidenceDisclosureIntegrityError('The disclosure package does not match its encrypted management record.', { bundleId });
    }
    return Object.freeze({
      valid: true,
      sealed: true,
      metadataOnly: true,
      bundleId,
      evidenceId: record.evidenceId,
      recipientId: record.recipientId,
      signingKeyId: record.signingKeyId,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      manifestSha256: record.manifestSha256,
      ciphertextSha256: signature.ciphertextSha256
    });
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock(`evidence-disclosure:${tenant}`, () => {
      const paths = tenantPaths(tenant);
      const packages = new Set(packageNames(paths.packages).map((name) => name.slice(0, -7)));
      const records = new Set(recordNames(paths.records).map((name) => name.slice(0, -7)));
      const orphanPackages = [...packages].filter((id) => !records.has(id));
      const orphanRecords = [...records].filter((id) => !packages.has(id));
      if (orphanPackages.length || orphanRecords.length) {
        throw new EvidenceDisclosureIntegrityError('Disclosure package and management record sets do not match.', {
          orphanPackageCount: orphanPackages.length,
          orphanRecordCount: orphanRecords.length
        });
      }
      for (const id of records) verifyLocked(tenant, id);
      return { valid: true, tenantId: tenant, checkedBundles: records.size, orphanPackageCount: 0, orphanRecordCount: 0 };
    });
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    try {
      const paths = tenantPaths(tenant);
      const packages = new Set(packageNames(paths.packages).map((name) => name.slice(0, -7)));
      const records = new Set(recordNames(paths.records).map((name) => name.slice(0, -7)));
      const orphanPackageCount = [...packages].filter((id) => !records.has(id)).length;
      const orphanRecordCount = [...records].filter((id) => !packages.has(id)).length;
      return {
        status: orphanPackageCount || orphanRecordCount ? 'unavailable' : 'ready',
        enabled: true,
        bundleCount: records.size,
        orphanPackageCount,
        orphanRecordCount,
        rawEvidenceIncluded: false
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        status: 'ready',
        enabled: true,
        mode: 'recipient-encrypted-portable-disclosures',
        recipientCount: recipientKeyring.size,
        signingKeyCount: enterpriseSigning.keys.size,
        primarySigningKeyId: enterpriseSigning.primaryKeyId,
        metadataOnly: true,
        recipientPrivateKeysStored: false,
        rawEvidenceIncluded: false,
        maximumPayloadBytes: payloadLimit,
        defaultExpiryDays: expiryDays,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, mode: 'recipient-encrypted-portable-disclosures', error: error?.code ?? 'evidence_disclosure_store_unavailable' };
    }
  }

  function bundlePaths(tenant, bundleId) {
    const paths = tenantPaths(tenant);
    return {
      package: resolve(paths.packages, `${bundleId}.bundle`),
      record: resolve(paths.records, `${bundleId}.record`)
    };
  }
  function tenantPaths(tenant) {
    const tenantRoot = resolve(root, sha256(tenant));
    const packages = resolve(tenantRoot, 'packages');
    const records = resolve(tenantRoot, 'records');
    mkdirSync(packages, { recursive: true, mode: 0o700 });
    mkdirSync(records, { recursive: true, mode: 0o700 });
    return { packages, records };
  }
  function readRecord(path, tenant, bundleId) {
    try {
      const value = decryptEvidenceJson(readEvidenceJson(path), index, recordAad(tenant, bundleId), EvidenceDisclosureIntegrityError);
      if (!value || value.format !== RECORD_FORMAT || value.version !== 1 || value.tenantId !== tenant || value.bundleId !== bundleId) {
        throw new EvidenceDisclosureIntegrityError('The disclosure management record identity is invalid.', { bundleId });
      }
      return value;
    } catch (error) {
      if (error instanceof EvidenceDisclosureIntegrityError) throw error;
      throw new EvidenceDisclosureStoreError('The disclosure management record is unreadable.', { bundleId }, error);
    }
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    directory: root,
    create,
    list,
    packageFor,
    verify,
    verifyTenant,
    tenantStatus,
    health,
    enterprisePublicKeys: enterpriseSigning.publicKeys
  });
}

export function createEvidenceDisclosureBundleStoreFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_DISCLOSURE_MODE) ?? 'disabled';
  if (mode === 'disabled') return createEvidenceDisclosureBundleStore({ mode });
  if (!evidenceRegistry?.evidenceTimeAttestationEnabled) {
    throw new EvidenceDisclosureStoreError('Evidence disclosures require enabled independent time attestations.', { reason: 'time_attestations_disabled' });
  }
  const required = [
    'WORKFORCE_AUDIT_DISCLOSURE_INDEX_KEYS',
    'WORKFORCE_AUDIT_DISCLOSURE_INDEX_PRIMARY_KEY_ID',
    'WORKFORCE_AUDIT_DISCLOSURE_RECIPIENTS',
    'WORKFORCE_AUDIT_DISCLOSURE_SIGNING_KEYS',
    'WORKFORCE_AUDIT_DISCLOSURE_SIGNING_PRIMARY_KEY_ID'
  ];
  const missing = required.filter((name) => !environmentValue(env[name]));
  if (missing.length) throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is incomplete.', { reason: 'missing_configuration', missing });
  try {
    return createEvidenceDisclosureBundleStore({
      mode,
      directory: environmentValue(env.WORKFORCE_AUDIT_DISCLOSURE_DIR)
        ?? resolve(evidenceRegistry.evidencePreservationStore.directory, '.disclosures'),
      indexKeys: JSON.parse(env.WORKFORCE_AUDIT_DISCLOSURE_INDEX_KEYS),
      indexPrimaryKeyId: env.WORKFORCE_AUDIT_DISCLOSURE_INDEX_PRIMARY_KEY_ID,
      recipients: JSON.parse(env.WORKFORCE_AUDIT_DISCLOSURE_RECIPIENTS),
      signingKeys: JSON.parse(env.WORKFORCE_AUDIT_DISCLOSURE_SIGNING_KEYS),
      signingPrimaryKeyId: env.WORKFORCE_AUDIT_DISCLOSURE_SIGNING_PRIMARY_KEY_ID,
      defaultExpiryDays: Number(env.WORKFORCE_AUDIT_DISCLOSURE_DEFAULT_EXPIRY_DAYS ?? 30),
      maximumPayloadBytes: Number(env.WORKFORCE_AUDIT_DISCLOSURE_MAX_PAYLOAD_BYTES ?? 5_000_000)
    });
  } catch (error) {
    if (error instanceof EvidenceDisclosureStoreError) throw error;
    throw new EvidenceDisclosureStoreError('Evidence disclosure configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function parseRecipients(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure recipients must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 100) throw new TypeError('Disclosure recipients must contain 1 to 100 entries.');
  return new Map(entries.map(([recipientId, config]) => {
    identifier(recipientId, 'recipientId');
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Disclosure recipient ${recipientId} is invalid.`);
    const publicEntries = Object.entries(config.publicKeys ?? {});
    if (!publicEntries.length || publicEntries.length > 20) throw new TypeError(`Disclosure recipient ${recipientId} must contain public keys.`);
    const keys = new Map(publicEntries.map(([keyId, pem]) => {
      identifier(keyId, 'recipientKeyId');
      const key = createPublicKey(pem);
      if (key.asymmetricKeyType !== 'rsa' && key.asymmetricKeyType !== 'rsa-pss') throw new TypeError(`Disclosure recipient key ${recipientId}:${keyId} must be RSA.`);
      if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Disclosure recipient key ${recipientId}:${keyId} must be at least 2048 bits.`);
      return [keyId, key];
    }));
    const primaryKeyId = String(config.primaryKeyId ?? publicEntries[0][0]);
    if (!keys.has(primaryKeyId)) throw new TypeError(`Disclosure recipient ${recipientId} primary key is unavailable.`);
    return [recipientId, Object.freeze({ keys, primaryKeyId })];
  }));
}

function parseSigningKeys(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Disclosure signing keys must be an object.');
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 20) throw new TypeError('Disclosure signing keys must contain 1 to 20 entries.');
  const keys = new Map();
  const publicKeys = new Map();
  for (const [keyId, value] of entries) {
    identifier(keyId, 'signingKeyId');
    const privateKey = createPrivateKey(typeof value === 'string' ? value : value?.privateKey);
    let algorithm;
    if (privateKey.asymmetricKeyType === 'ed25519') algorithm = 'ed25519';
    else if (privateKey.asymmetricKeyType === 'rsa' || privateKey.asymmetricKeyType === 'rsa-pss') {
      if ((privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Disclosure signing key ${keyId} must be at least 2048 bits.`);
      algorithm = 'rsa-pss-sha256';
    } else throw new TypeError(`Disclosure signing key ${keyId} must be Ed25519 or RSA.`);
    keys.set(keyId, Object.freeze({ privateKey, algorithm }));
    publicKeys.set(keyId, createPublicKey(privateKey));
  }
  const primary = String(primaryKeyId ?? entries[0][0]);
  if (!keys.has(primary)) throw new TypeError('The disclosure primary signing key is unavailable.');
  return Object.freeze({ keys, publicKeys, primaryKeyId: primary });
}

function signEnvelope(envelope, signing) {
  const bytes = Buffer.from(disclosurePackageSignatureBody(envelope));
  return signing.algorithm === 'ed25519'
    ? signValue(null, bytes, signing.privateKey)
    : signValue('sha256', bytes, {
      key: signing.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    });
}

function validateCreateInput(input, context) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A disclosure bundle request is required.');
  if (!input.payloadBody || typeof input.payloadBody !== 'object' || Array.isArray(input.payloadBody)) throw new EvidenceValidationError('A disclosure payload body is required.');
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    evidenceId: evidenceIdentifier(input.evidenceId),
    recipientId: identifier(input.recipientId, 'recipientId'),
    idempotencyKey: identifier(input.idempotencyKey, 'idempotencyKey'),
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    expiresAt: input.expiresAt ? validDate(input.expiresAt, 'expiresAt') : null,
    actor: identifier(context.actor, 'actor'),
    payloadBody: input.payloadBody
  };
}
function publicRecord(record) {
  return {
    bundleId: record.bundleId,
    evidenceId: record.evidenceId,
    recipientId: record.recipientId,
    recipientKeyId: record.recipientKeyId,
    signingKeyId: record.signingKeyId,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    purpose: record.purpose,
    actor: record.actor,
    manifestSha256: record.manifestSha256,
    payloadSha256: record.payloadSha256,
    ciphertextSha256: record.ciphertextSha256,
    versionCount: record.versionCount,
    rawEvidenceIncluded: false
  };
}
function writeJsonExclusive(path, value, bundleId) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  let descriptor = null;
  let created = false;
  let committed = false;
  try {
    descriptor = openSync(path, 'wx', 0o600);
    created = true;
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    committed = true;
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    if (error?.code === 'EEXIST') throw new EvidenceDisclosureIntegrityError('A conflicting create-only disclosure record exists.', { bundleId });
    throw new EvidenceDisclosureStoreError('A disclosure record could not be committed.', { bundleId, created, committed }, error);
  }
}
function packageNames(directory) { return readdirSync(directory).filter((name) => BUNDLE_ID.test(name.slice(0, -7)) && name.endsWith('.bundle')).sort(); }
function recordNames(directory) { return readdirSync(directory).filter((name) => BUNDLE_ID.test(name.slice(0, -7)) && name.endsWith('.record')).sort(); }
function recordAad(tenantId, bundleId) { return `basitclaw:evidence-disclosure:record:${tenantId}:${bundleId}`; }
function bundleIdentifier(value) { const id = String(value ?? ''); if (!BUNDLE_ID.test(id)) throw new EvidenceValidationError('bundleId is invalid.', { field: 'bundleId' }); return id; }
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function validDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid date.`, { field }); return date; }
function integer(value, field, minimum, maximum) { const number = Number(value); if (!Number.isInteger(number) || number < minimum || number > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return number; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function environmentValue(value) { const text = typeof value === 'string' ? value.trim() : value; return text === '' || text === null || text === undefined ? undefined : text; }
function storeFailure(error, operation, bundleId) { if (error instanceof EvidenceDisclosureStoreError || error instanceof EvidenceDisclosureIntegrityError) return error; return new EvidenceDisclosureStoreError('The disclosure operation failed.', { operation, bundleId }, error); }
function disabledStore() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled', rawEvidenceIncluded: false });
  return Object.freeze({
    mode: 'disabled', enabled: false,
    create() { throw new EvidenceConflictError('Evidence disclosures are disabled.'); },
    list() { return []; },
    packageFor() { throw new EvidenceConflictError('Evidence disclosures are disabled.'); },
    verify() { throw new EvidenceConflictError('Evidence disclosures are disabled.'); },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedBundles: 0, orphanPackageCount: 0, orphanRecordCount: 0 }; },
    tenantStatus() { return status; },
    health() { return status; },
    enterprisePublicKeys: new Map()
  });
}
