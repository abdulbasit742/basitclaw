import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomUUID,
  sign as signAsymmetric,
  timingSafeEqual,
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
  strictBase64
} from './evidenceCrypto.js';
import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import {
  EvidenceAssuranceBundleAuthenticationError,
  EvidenceAssuranceBundleStoreError
} from './evidenceAssuranceBundleStore.js';

const RECORD_FORMAT = 'basitclaw-assurance-acceptance-record';
const RECEIPT_FORMAT = 'basitclaw-assurance-acceptance-receipt';
const PACKAGE_FORMAT = 'basitclaw-assurance-bundle-package';
const BUNDLE_ID = /^ASB-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'enforce']);

export class EvidenceAssuranceAcceptanceRequiredError extends EvidenceConflictError {
  constructor(bundleId = null, details = {}) {
    super('A verified recipient acceptance receipt is required before assurance bundle delivery can complete.', {
      bundleId,
      ...details
    });
    this.name = 'EvidenceAssuranceAcceptanceRequiredError';
    this.code = 'EVIDENCE_ASSURANCE_ACCEPTANCE_REQUIRED';
  }
}

export function createEvidenceAssuranceAcceptanceStore({
  bundles,
  mode = 'disabled',
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  signingKeys,
  signingPrimaryKeyId,
  recipients = {},
  clockSkewSeconds = 300,
  maxRecords = 100_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  if (!bundles || typeof bundles.queue !== 'function' || typeof bundles.acknowledgeSigned !== 'function') {
    throw new TypeError('An assurance bundle store is required.');
  }
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledAcceptanceStore(bundles);
  if (!String(directory ?? '').trim()) throw new TypeError('An assurance acceptance directory is required.');

  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const signing = parseSigningKeys(signingKeys, signingPrimaryKeyId);
  const recipientMap = parseRecipientHmacKeys(recipients);
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 10, 3600) * 1000;
  const recordLimit = integer(maxRecords, 'maxRecords', 100, 1_000_000);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function queue(input) {
    const result = bundles.queue(input);
    const expected = expectationFor(input, result.bundle);
    return lock.withLock(`assurance-acceptance:${expected.recipientId}`, () => {
      const path = recordPath(expected.recipientId, expected.bundleId);
      if (existsSync(path)) {
        const current = readRecord(path, expected.recipientId, expected.bundleId);
        if (current.acceptanceReceipt) {
          assertExpectation(current.expected, expected);
          return result;
        }
        if (!sameExpectation(current.expected, expected)) {
          current.expected = expected;
          current.updatedAt = now().toISOString();
          writeRecord(path, current, expected.recipientId, expected.bundleId);
        }
        return result;
      }
      if (recordNames(expected.recipientId).length >= recordLimit) {
        throw new EvidenceAssuranceBundleStoreError('The assurance acceptance store has reached capacity.', {
          reason: 'acceptance_record_capacity', maxRecords: recordLimit
        });
      }
      writeRecord(path, {
        format: RECORD_FORMAT,
        version: 1,
        recipientId: expected.recipientId,
        bundleId: expected.bundleId,
        tenantId: expected.tenantId,
        evidenceId: expected.evidenceId,
        evidenceVersion: expected.evidenceVersion,
        expected,
        acceptanceReceipt: null,
        createdAt: now().toISOString(),
        updatedAt: now().toISOString()
      }, expected.recipientId, expected.bundleId);
      return result;
    });
  }

  function acknowledgeSigned(bundleId) {
    throw new EvidenceAssuranceAcceptanceRequiredError(bundleIdentifier(bundleId), {
      endpoint: `/api/workforce-audit/assurance-recipient/bundles/${bundleId}/acceptance`
    });
  }

  function acceptAndAcknowledgeSigned(bundleId, bodyBytes, headers) {
    const id = bundleIdentifier(bundleId);
    const auth = authenticateSigned(bodyBytes, headers, `acceptance:${id}`);
    return lock.withLock(`assurance-acceptance:${auth.recipientId}`, () => {
      registerReplay(auth);
      const input = parseAcceptance(bodyBytes);
      const path = recordPath(auth.recipientId, id);
      if (!existsSync(path)) throw new EvidenceValidationError('The assurance acceptance expectation was not found.', { bundleId: id });
      const record = readRecord(path, auth.recipientId, id);
      const expected = record.expected;
      if (record.acceptanceReceipt) {
        assertAcceptanceMatches(record.acceptanceReceipt, input, auth);
        return { duplicate: true, bundle: deliveredBundle(expected), acceptanceReceipt: publicReceipt(record.acceptanceReceipt) };
      }
      validateAcceptance(input, expected, auth, now, skewMs);

      const acknowledgement = makeInternalAcknowledgement(id, auth, input, recipientMap, now);
      const delivered = bundles.acknowledgeSigned(id, acknowledgement.body, acknowledgement.headers);
      const receipt = signAcceptanceReceipt({
        format: RECEIPT_FORMAT,
        version: 1,
        acceptanceId: `AAR-${sha256([id, auth.recipientId, expected.packageSha256, input.verifiedAt].join('|')).slice(0, 32)}`,
        bundleId: id,
        tenantId: expected.tenantId,
        evidenceId: expected.evidenceId,
        evidenceVersion: expected.evidenceVersion,
        recipientId: auth.recipientId,
        recipientHmacKeyId: auth.keyId,
        recipientPublicKeyId: expected.recipientPublicKeyId,
        packageSha256: expected.packageSha256,
        plaintextSha256: expected.plaintextSha256,
        bundleDigest: expected.bundleDigest,
        sectionDigestsSha256: expected.sectionDigestsSha256,
        contentSha256: expected.contentSha256,
        verifiedAt: input.verifiedAt,
        verifierVersion: input.verifierVersion,
        verificationOutcome: 'verified',
        recipientRequestBodySha256: sha256(bodyBytes),
        acknowledgedAt: delivered.deliveredAt ?? now().toISOString(),
        recordedAt: now().toISOString()
      }, signing);
      record.acceptanceReceipt = receipt;
      record.updatedAt = now().toISOString();
      writeRecord(path, record, auth.recipientId, id);
      return { duplicate: false, bundle: { ...delivered, acceptanceStatus: 'verified' }, acceptanceReceipt: publicReceipt(receipt) };
    });
  }

  function list(tenantId, options = {}) {
    const rows = bundles.list(tenantId, options);
    return rows.map((bundle) => {
      const record = readOptionalRecord(bundle.recipientId, bundle.bundleId);
      return {
        ...bundle,
        acceptanceStatus: record?.acceptanceReceipt
          ? 'verified'
          : bundle.state === 'delivered' ? 'unverified' : 'pending',
        acceptanceReceipt: record?.acceptanceReceipt ? publicReceipt(record.acceptanceReceipt) : null
      };
    });
  }

  function acceptanceReceipts(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const rows = [];
    for (const recipientId of recipientMap.keys()) {
      for (const filename of recordNames(recipientId)) {
        const bundleId = filename.slice(0, -11);
        const record = readRecord(recordPath(recipientId, bundleId), recipientId, bundleId);
        if (record.tenantId !== tenant || !record.acceptanceReceipt || (evidence && record.evidenceId !== evidence)) continue;
        rows.push(publicReceipt(record.acceptanceReceipt));
      }
    }
    return rows.sort((a, b) => b.recordedAt.localeCompare(a.recordedAt)).slice(0, integer(limit, 'limit', 1, 5000));
  }

  function verifyAcceptanceReceipt(tenantId, bundleId) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = bundleIdentifier(bundleId);
    for (const recipientId of recipientMap.keys()) {
      const record = readOptionalRecord(recipientId, id);
      if (!record || record.tenantId !== tenant) continue;
      if (!record.acceptanceReceipt) throw new EvidenceAssuranceAcceptanceRequiredError(id);
      verifyReceipt(record.acceptanceReceipt, signing);
      assertReceiptExpectation(record.acceptanceReceipt, record.expected);
      return { valid: true, acceptanceReceipt: publicReceipt(record.acceptanceReceipt) };
    }
    throw new EvidenceValidationError('The assurance acceptance receipt was not found.', { bundleId: id });
  }

  function tenantStatus(tenantId) {
    const base = bundles.tenantStatus(tenantId);
    const rows = list(tenantId, { limit: 5000 });
    const verified = rows.filter((row) => row.acceptanceStatus === 'verified').length;
    const deliveredUnverified = rows.filter((row) => row.acceptanceStatus === 'unverified').length;
    return {
      ...base,
      status: deliveredUnverified ? 'attention' : base.status,
      verifiedAcceptanceRequired: true,
      verifiedAcceptances: verified,
      deliveredUnverified
    };
  }

  function health() {
    const base = bundles.health();
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      return {
        ...base,
        verifiedAcceptanceRequired: true,
        signedAcceptanceReceipts: true,
        acceptanceSigningAlgorithm: 'ed25519',
        acceptanceSigningKeyId: signing.primaryKeyId,
        acceptanceSigningKeyFingerprint: signing.keys.get(signing.primaryKeyId).fingerprint,
        acceptanceRecordEncryption: 'aes-256-gcm',
        acceptanceRecordCount: [...recipientMap.keys()].reduce((sum, recipientId) => sum + recordNames(recipientId).length, 0)
      };
    } catch (error) {
      return { ...base, status: 'unavailable', verifiedAcceptanceRequired: true, error: error?.code ?? 'assurance_acceptance_store_unavailable' };
    }
  }

  function readOptionalRecord(recipientId, bundleId) {
    const path = recordPath(recipientId, bundleId);
    return existsSync(path) ? readRecord(path, recipientId, bundleId) : null;
  }

  function authenticateSigned(bodyBytes, headers, operation) {
    const recipientId = identifier(header(headers, 'x-basitclaw-recipient-id'), 'recipientId');
    const keyId = keyIdentifier(header(headers, 'x-basitclaw-recipient-key-id'));
    const timestamp = isoDate(header(headers, 'x-basitclaw-recipient-timestamp'), 'timestamp');
    const nonce = nonceValue(header(headers, 'x-basitclaw-recipient-nonce'));
    const secret = recipientMap.get(recipientId)?.hmacKeys.get(keyId);
    if (!secret) throw new EvidenceAssuranceBundleAuthenticationError();
    if (Math.abs(now().getTime() - new Date(timestamp).getTime()) > skewMs) {
      throw new EvidenceAssuranceBundleAuthenticationError('The assurance acceptance timestamp is outside the accepted window.', { reason: 'timestamp_window' });
    }
    const canonical = [recipientId, keyId, operation, timestamp, nonce, sha256(bodyBytes)].join('\n');
    const expected = createHmac('sha256', secret).update(canonical).digest();
    let supplied;
    try { supplied = strictBase64(header(headers, 'x-basitclaw-recipient-signature'), 'recipient signature'); }
    catch { throw new EvidenceAssuranceBundleAuthenticationError(); }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new EvidenceAssuranceBundleAuthenticationError();
    return { recipientId, keyId, timestamp, nonce, replayId: sha256(canonical) };
  }

  function registerReplay(auth) {
    const path = resolve(recipientRoot(auth.recipientId), '.acceptance-replay', `${auth.replayId}.nonce`);
    if (existsSync(path)) throw new EvidenceAssuranceBundleAuthenticationError('The assurance acceptance request was already used.', { reason: 'replay' });
    atomicWriteEvidenceJson(path, { timestamp: auth.timestamp, nonceHash: sha256(auth.nonce) });
  }

  function readRecord(path, recipientId, bundleId) {
    try {
      const record = decryptEvidenceJson(readEvidenceJson(path), encryption, recordAad(recipientId, bundleId), EvidenceIntegrityError);
      if (!record || record.format !== RECORD_FORMAT || record.version !== 1
          || record.recipientId !== recipientId || record.bundleId !== bundleId) {
        throw new EvidenceIntegrityError('The assurance acceptance record identity is invalid.', { bundleId });
      }
      if (record.acceptanceReceipt) verifyReceipt(record.acceptanceReceipt, signing);
      return record;
    } catch (error) {
      if (error instanceof EvidenceIntegrityError) throw error;
      throw new EvidenceAssuranceBundleStoreError('The assurance acceptance record is unreadable.', { bundleId }, error);
    }
  }

  function writeRecord(path, record, recipientId, bundleId) {
    atomicWriteEvidenceJson(path, encryptEvidenceJson(record, encryption, recordAad(recipientId, bundleId)));
  }

  function recipientRoot(recipientId) {
    const path = resolve(root, sha256(`recipient:${recipientId}`));
    mkdirSync(path, { recursive: true, mode: 0o700 });
    return path;
  }
  function recordPath(recipientId, bundleId) { return resolve(recipientRoot(recipientId), `${bundleId}.acceptance`); }
  function recordNames(recipientId) { return readdirSync(recipientRoot(recipientId)).filter((name) => name.endsWith('.acceptance') && BUNDLE_ID.test(name.slice(0, -11))).sort(); }

  return Object.freeze({
    ...bundles,
    mode: bundles.mode,
    enabled: bundles.enabled,
    required: bundles.required,
    verifiedAcceptanceRequired: true,
    queue,
    list,
    acknowledgeSigned,
    acceptAndAcknowledgeSigned,
    acceptanceReceipts,
    verifyAcceptanceReceipt,
    tenantStatus,
    health
  });
}

export function createEvidenceAssuranceAcceptanceStoreFromEnvironment({ env = process.env, bundles } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_MODE) ?? 'disabled';
  if (mode === 'disabled') return createEvidenceAssuranceAcceptanceStore({ bundles, mode });
  const keysRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_KEYS);
  const primaryKeyId = envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_PRIMARY_KEY_ID);
  const signingRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_SIGNING_KEYS);
  const signingPrimaryKeyId = envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_PRIMARY_SIGNING_KEY_ID);
  const recipientsRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENTS);
  if (!keysRaw || !primaryKeyId || !signingRaw || !signingPrimaryKeyId || !recipientsRaw) {
    throw new EvidenceAssuranceBundleStoreError('Dedicated assurance acceptance encryption, signing and recipient keys are required.', {
      reason: 'missing_acceptance_configuration'
    });
  }
  try {
    return createEvidenceAssuranceAcceptanceStore({
      bundles,
      mode,
      directory: envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_DIR)
        ?? '.runtime-data/workforce-audit-assurance-acceptance',
      encryptionKeys: JSON.parse(keysRaw),
      encryptionPrimaryKeyId: primaryKeyId,
      signingKeys: JSON.parse(signingRaw),
      signingPrimaryKeyId,
      recipients: JSON.parse(recipientsRaw),
      clockSkewSeconds: envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_CLOCK_SKEW_SECONDS) ?? 300,
      maxRecords: envValue(env.WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_MAX_RECORDS) ?? 100_000
    });
  } catch (error) {
    if (error instanceof EvidenceAssuranceBundleStoreError) throw error;
    throw new EvidenceAssuranceBundleStoreError('Assurance acceptance configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function expectationFor(input, bundle) {
  const packagePayload = {
    format: PACKAGE_FORMAT,
    version: 1,
    bundleId: bundle.bundleId,
    tenantId: input.tenantId,
    evidenceId: input.evidenceId,
    evidenceVersion: input.evidenceVersion,
    recipientId: input.recipientId,
    createdAt: bundle.createdAt,
    expiresAt: bundle.expiresAt,
    purpose: input.purpose,
    requestedBy: input.requestedBy,
    manifest: input.manifest,
    evidence: input.evidence
  };
  return {
    bundleId: bundle.bundleId,
    tenantId: identifier(input.tenantId, 'tenantId'),
    evidenceId: evidenceIdentifier(input.evidenceId),
    evidenceVersion: integer(input.evidenceVersion, 'evidenceVersion', 1, 1_000_000),
    contentSha256: hashValue(input.contentSha256, 'contentSha256'),
    recipientId: identifier(input.recipientId, 'recipientId'),
    recipientPublicKeyId: keyIdentifier(bundle.recipientPublicKeyId),
    packageSha256: hashValue(bundle.packageSha256, 'packageSha256'),
    plaintextSha256: sha256(stableStringify(packagePayload)),
    bundleDigest: hashValue(input.manifest.bundleDigest, 'bundleDigest'),
    sectionDigestsSha256: sha256(stableStringify(input.manifest.sectionDigests)),
    createdAt: isoDate(bundle.createdAt, 'createdAt'),
    expiresAt: isoDate(bundle.expiresAt, 'expiresAt')
  };
}

function parseAcceptance(bodyBytes) {
  const input = parseStrictJson(bodyBytes, new Set([
    'claimToken', 'packageSha256', 'plaintextSha256', 'bundleDigest',
    'sectionDigestsSha256', 'verifiedAt', 'verifierVersion'
  ]));
  return {
    claimToken: cleanText(input.claimToken, 'claimToken', 20, 500),
    packageSha256: hashValue(input.packageSha256, 'packageSha256'),
    plaintextSha256: hashValue(input.plaintextSha256, 'plaintextSha256'),
    bundleDigest: hashValue(input.bundleDigest, 'bundleDigest'),
    sectionDigestsSha256: hashValue(input.sectionDigestsSha256, 'sectionDigestsSha256'),
    verifiedAt: isoDate(input.verifiedAt, 'verifiedAt'),
    verifierVersion: cleanText(input.verifierVersion, 'verifierVersion', 3, 100)
  };
}

function validateAcceptance(input, expected, auth, now, skewMs) {
  if (auth.recipientId !== expected.recipientId) throw new EvidenceAssuranceBundleAuthenticationError();
  for (const field of ['packageSha256', 'plaintextSha256', 'bundleDigest', 'sectionDigestsSha256']) {
    if (!safeEqual(input[field], expected[field])) {
      throw new EvidenceIntegrityError(`The assurance acceptance ${field} does not match the issued bundle.`, { bundleId: expected.bundleId, field });
    }
  }
  const verified = new Date(input.verifiedAt);
  if (verified.getTime() > now().getTime() + skewMs || verified < new Date(expected.createdAt)) {
    throw new EvidenceValidationError('verifiedAt is outside the assurance bundle verification window.', { field: 'verifiedAt' });
  }
}

function makeInternalAcknowledgement(bundleId, auth, input, recipients, now) {
  const body = Buffer.from(JSON.stringify({ claimToken: input.claimToken, packageSha256: input.packageSha256 }));
  const timestamp = now().toISOString();
  const nonce = `acceptance-internal-${randomUUID()}`;
  const operation = `acknowledge:${bundleId}`;
  const canonical = [auth.recipientId, auth.keyId, operation, timestamp, nonce, sha256(body)].join('\n');
  const secret = recipients.get(auth.recipientId).hmacKeys.get(auth.keyId);
  const signature = createHmac('sha256', secret).update(canonical).digest('base64');
  return {
    body,
    headers: {
      'x-basitclaw-recipient-id': auth.recipientId,
      'x-basitclaw-recipient-key-id': auth.keyId,
      'x-basitclaw-recipient-timestamp': timestamp,
      'x-basitclaw-recipient-nonce': nonce,
      'x-basitclaw-recipient-signature': signature
    }
  };
}

function signAcceptanceReceipt(body, signing) {
  const key = signing.keys.get(signing.primaryKeyId);
  return {
    ...body,
    signingAlgorithm: 'ed25519',
    signingKeyId: signing.primaryKeyId,
    signingKeyFingerprint: key.fingerprint,
    signature: signAsymmetric(null, Buffer.from(stableStringify(body)), key.privateKey).toString('base64')
  };
}

function verifyReceipt(receipt, signing) {
  const key = signing.keys.get(receipt.signingKeyId);
  if (!key || receipt.signingAlgorithm !== 'ed25519' || receipt.signingKeyFingerprint !== key.fingerprint) {
    throw new EvidenceIntegrityError('The assurance acceptance receipt signing identity is invalid.', { acceptanceId: receipt.acceptanceId });
  }
  const { signingAlgorithm, signingKeyId, signingKeyFingerprint, signature, ...body } = receipt;
  let signatureBytes;
  try { signatureBytes = strictBase64(signature, 'acceptance receipt signature'); }
  catch (error) { throw new EvidenceIntegrityError('The assurance acceptance receipt signature is invalid.', {}, error); }
  if (!verifyAsymmetric(null, Buffer.from(stableStringify(body)), key.publicKey, signatureBytes)) {
    throw new EvidenceIntegrityError('The assurance acceptance receipt signature verification failed.', { acceptanceId: receipt.acceptanceId });
  }
}

function assertReceiptExpectation(receipt, expected) {
  for (const field of ['bundleId', 'tenantId', 'evidenceId', 'evidenceVersion', 'recipientId', 'recipientPublicKeyId', 'packageSha256', 'plaintextSha256', 'bundleDigest', 'sectionDigestsSha256', 'contentSha256']) {
    if (receipt[field] !== expected[field]) throw new EvidenceIntegrityError('The assurance acceptance receipt does not match its issued bundle.', { bundleId: expected.bundleId, field });
  }
}
function assertAcceptanceMatches(receipt, input, auth) { if (receipt.recipientId !== auth.recipientId || receipt.recipientHmacKeyId !== auth.keyId || receipt.packageSha256 !== input.packageSha256 || receipt.plaintextSha256 !== input.plaintextSha256 || receipt.bundleDigest !== input.bundleDigest || receipt.sectionDigestsSha256 !== input.sectionDigestsSha256 || receipt.verifiedAt !== input.verifiedAt || receipt.verifierVersion !== input.verifierVersion) throw new EvidenceConflictError('A conflicting assurance acceptance receipt already exists.', { bundleId: receipt.bundleId }); }
function assertExpectation(left, right) { if (!sameExpectation(left, right)) throw new EvidenceIntegrityError('The assurance acceptance expectation conflicts with the issued bundle.', { bundleId: right.bundleId }); }
function sameExpectation(left, right) { return stableStringify(left) === stableStringify(right); }
function deliveredBundle(expected) { return { bundleId: expected.bundleId, evidenceId: expected.evidenceId, evidenceVersion: expected.evidenceVersion, recipientId: expected.recipientId, recipientPublicKeyId: expected.recipientPublicKeyId, packageSha256: expected.packageSha256, state: 'delivered', acceptanceStatus: 'verified' }; }
function publicReceipt(receipt) { const { tenantId, ...publicFields } = receipt; return structuredClone(publicFields); }
function recordAad(recipientId, bundleId) { return `basitclaw:assurance-acceptance:${recipientId}:${bundleId}`; }
function parseSigningKeys(raw, primaryKeyId) { if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Assurance acceptance signing keys must be an object.'); const keys = new Map(Object.entries(raw).map(([keyId, pem]) => { keyIdentifier(keyId); const privateKey = createPrivateKey(String(pem)); if (privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Assurance acceptance signing key ${keyId} must be Ed25519.`); const publicKey = createPublicKey(privateKey); return [keyId, { privateKey, publicKey, fingerprint: sha256(publicKey.export({ type: 'spki', format: 'der' })) }]; })); if (!keys.size || keys.size > 20) throw new TypeError('Assurance acceptance signing keys must contain 1 to 20 entries.'); const primary = keyIdentifier(primaryKeyId); if (!keys.has(primary)) throw new TypeError('The assurance acceptance primary signing key is unavailable.'); return Object.freeze({ keys, primaryKeyId: primary }); }
function parseRecipientHmacKeys(raw) { if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Assurance recipients must be an object.'); const result = new Map(); for (const [recipientId, value] of Object.entries(raw)) { identifier(recipientId, 'recipientId'); const hmacKeys = new Map(Object.entries(value?.keys ?? {}).map(([keyId, encoded]) => { keyIdentifier(keyId); const secret = strictBase64(encoded, `recipient secret ${recipientId}/${keyId}`); if (secret.length < 32 || secret.length > 128) throw new TypeError(`Assurance recipient ${recipientId} HMAC keys must decode to 32 to 128 bytes.`); return [keyId, secret]; })); if (!hmacKeys.size) throw new TypeError(`Assurance recipient ${recipientId} needs at least one HMAC key.`); result.set(recipientId, Object.freeze({ hmacKeys })); } return result; }
function parseStrictJson(bytes, allowed) { let input; try { input = JSON.parse(Buffer.from(bytes).toString('utf8') || '{}'); } catch { throw new EvidenceValidationError('The assurance acceptance request must contain valid JSON.', { field: 'body' }); } if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('The assurance acceptance request body must be an object.', { field: 'body' }); for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Unsupported assurance acceptance field ${key}.`, { field: key }); return input; }
function header(headers, name) { const value = headers?.[name] ?? headers?.[name.toLowerCase()]; return Array.isArray(value) ? value[0] : String(value ?? ''); }
function safeEqual(left, right) { if (!left || !right) return false; const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function keyIdentifier(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(text)) throw new EvidenceValidationError('keyId is invalid.', { field: 'keyId' }); return text; }
function bundleIdentifier(value) { const text = String(value ?? ''); if (!BUNDLE_ID.test(text)) throw new EvidenceValidationError('bundleId is invalid.', { field: 'bundleId' }); return text; }
function evidenceIdentifier(value) { const text = String(value ?? ''); if (!EVIDENCE_ID.test(text)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return text; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function nonceValue(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9._:-]{16,191}$/.test(text)) throw new EvidenceAssuranceBundleAuthenticationError(); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function cleanText(value, field, min, max) { const text = String(value ?? '').trim(); if (text.length < min || text.length > max) throw new EvidenceValidationError(`${field} must contain ${min} to ${max} characters.`, { field }); return text; }
function integer(value, field, min, max) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new EvidenceValidationError(`${field} must be an integer from ${min} to ${max}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }

function disabledAcceptanceStore(bundles) {
  return Object.freeze({
    ...bundles,
    verifiedAcceptanceRequired: false,
    acceptAndAcknowledgeSigned() { throw new EvidenceConflictError('Verified assurance acceptance is disabled.'); },
    acceptanceReceipts() { return []; },
    verifyAcceptanceReceipt() { throw new EvidenceConflictError('Verified assurance acceptance is disabled.'); }
  });
}
