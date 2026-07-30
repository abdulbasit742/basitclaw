import {
  constants,
  createCipheriv,
  createHmac,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
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
import {
  createEvidenceAssuranceReceiptStore,
  createEvidenceAssuranceReceiptStoreFromEnvironment
} from './evidenceAssuranceReceiptStore.js';

const FORMAT = 'basitclaw-assurance-bundle-record';
const PACKAGE_FORMAT = 'basitclaw-assurance-bundle-package';
const SEALED_FORMAT = 'basitclaw-recipient-sealed-assurance-bundle';
const BUNDLE_ID = /^ASB-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const MODES = new Set(['disabled', 'pull']);
const DEFAULT_CLAIM_LEASE_MS = 300_000;
const DAY_MS = 86_400_000;

export class EvidenceAssuranceBundleStoreError extends EvidenceStoreError {
  constructor(message = 'The assurance bundle store is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceAssuranceBundleStoreError';
    this.code = 'EVIDENCE_ASSURANCE_BUNDLE_STORE_UNAVAILABLE';
  }
}
export class EvidenceAssuranceBundleAuthenticationError extends EvidenceConflictError {
  constructor(message = 'The assurance recipient request could not be authenticated.', details = {}) {
    super(message, details);
    this.name = 'EvidenceAssuranceBundleAuthenticationError';
    this.code = 'EVIDENCE_ASSURANCE_RECIPIENT_AUTHENTICATION_FAILED';
    this.statusCode = 401;
  }
}

export function createEvidenceAssuranceBundleStore({
  mode = 'disabled',
  required = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  recipients = {},
  deliveryReceipts = createEvidenceAssuranceReceiptStore({ mode: 'disabled' }),
  bundleTtlMinutes = 1440,
  claimLeaseMs = DEFAULT_CLAIM_LEASE_MS,
  maximumClaimBytes = 25_000_000,
  retention = 10_000,
  clockSkewSeconds = 300,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required assurance bundle delivery cannot be disabled.');
    return disabledStore();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An assurance bundle directory is required.');
  if (!deliveryReceipts || typeof deliveryReceipts.verifyAndRecord !== 'function') throw new TypeError('An assurance delivery receipt store is required.');
  const root = resolve(String(directory));
  const encryption = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const recipientMap = parseRecipients(recipients);
  if (!recipientMap.size) throw new TypeError('At least one assurance recipient is required.');
  const ttlMs = integer(bundleTtlMinutes, 'bundleTtlMinutes', 5, 43_200) * 60_000;
  const leaseMs = integer(claimLeaseMs, 'claimLeaseMs', 5_000, 3_600_000);
  const claimBytes = integer(maximumClaimBytes, 'maximumClaimBytes', 1024, 100_000_000);
  const retained = integer(retention, 'retention', 100, 100_000);
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 10, 3600) * 1000;
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });
  mkdirSync(root, { recursive: true, mode: 0o700 });

  function queue(input) {
    const source = validateQueueInput(input, recipientMap, now, ttlMs);
    const bundleId = bundleIdFor(source);
    const recipient = recipientMap.get(source.recipientId);
    const path = bundlePath(source.recipientId, bundleId);
    return lock.withLock(`assurance-bundles:${source.recipientId}`, () => {
      maintenanceLocked(source.recipientId);
      if (existsSync(path)) {
        const existing = readRecord(path, source.recipientId, bundleId);
        assertSameBundle(existing, source);
        if (existing.state !== 'expired') return { duplicate: true, resealed: false, bundle: publicRecord(existing) };
        const resealed = makeRecord(source, bundleId, recipient);
        replaceRecord(path, resealed, source.recipientId, bundleId);
        return { duplicate: false, resealed: true, bundle: publicRecord(resealed) };
      }
      const record = makeRecord(source, bundleId, recipient);
      writeRecordExclusive(path, record, source.recipientId, bundleId);
      pruneLocked(source.recipientId);
      return { duplicate: false, resealed: false, bundle: publicRecord(record) };
    });
  }

  function makeRecord(source, bundleId, recipient) {
    const packagePayload = {
      format: PACKAGE_FORMAT,
      version: 1,
      bundleId,
      tenantId: source.tenantId,
      evidenceId: source.evidenceId,
      evidenceVersion: source.evidenceVersion,
      recipientId: source.recipientId,
      createdAt: source.createdAt,
      expiresAt: source.expiresAt,
      purpose: source.purpose,
      requestedBy: source.requestedBy,
      manifest: source.manifest,
      evidence: source.evidence
    };
    const sealedPackage = sealForRecipient(packagePayload, recipient, bundleId);
    return {
      format: FORMAT,
      version: 1,
      bundleId,
      tenantId: source.tenantId,
      evidenceId: source.evidenceId,
      evidenceVersion: source.evidenceVersion,
      contentSha256: source.contentSha256,
      recipientId: source.recipientId,
      recipientPublicKeyId: sealedPackage.recipientPublicKeyId,
      purpose: source.purpose,
      requestedBy: source.requestedBy,
      createdAt: source.createdAt,
      expiresAt: source.expiresAt,
      state: 'pending',
      claimTokenHash: null,
      claimedAt: null,
      claimExpiresAt: null,
      deliveredAt: null,
      packageSha256: sha256(stableStringify(sealedPackage)),
      deliveryReceiptId: null,
      deliveryReceiptRecordHash: null,
      sealedPackage
    };
  }

  function list(tenantId, { evidenceId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : evidenceIdentifier(evidenceId);
    const maximum = integer(limit, 'limit', 1, 5000);
    const rows = [];
    for (const recipientId of recipientMap.keys()) {
      lock.withLock(`assurance-bundles:${recipientId}`, () => {
        maintenanceLocked(recipientId);
        for (const filename of bundleNames(recipientId)) {
          const id = filename.slice(0, -7);
          const record = readRecord(bundlePath(recipientId, id), recipientId, id);
          if (record.tenantId !== tenant || (evidence && record.evidenceId !== evidence)) continue;
          rows.push(publicRecord(record));
        }
      });
    }
    return rows.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, maximum);
  }

  function claimSigned(bodyBytes, headers) {
    const auth = authenticateSigned(bodyBytes, headers, 'claim');
    return lock.withLock(`assurance-bundles:${auth.recipientId}`, () => {
      registerReplay(auth);
      maintenanceLocked(auth.recipientId);
      const input = parseStrictJson(bodyBytes, new Set(['limit']));
      const limit = integer(input.limit ?? 1, 'limit', 1, 100);
      const selected = [];
      let responseBytes = 0;
      for (const filename of bundleNames(auth.recipientId)) {
        if (selected.length >= limit) break;
        const bundleId = filename.slice(0, -7);
        const path = bundlePath(auth.recipientId, bundleId);
        const record = readRecord(path, auth.recipientId, bundleId);
        if (record.state !== 'pending') continue;
        const estimate = Buffer.byteLength(JSON.stringify(record.sealedPackage)) + 1024;
        if (!selected.length && estimate > claimBytes) throw new EvidenceValidationError('The sealed assurance bundle exceeds the configured claim response limit.', { bundleId, maximumClaimBytes: claimBytes });
        if (responseBytes + estimate > claimBytes) break;
        const claimToken = randomBytes(32).toString('base64url');
        record.state = 'claimed';
        record.claimTokenHash = sha256(claimToken);
        record.claimedAt = now().toISOString();
        record.claimExpiresAt = new Date(now().getTime() + leaseMs).toISOString();
        replaceRecord(path, record, auth.recipientId, bundleId);
        responseBytes += estimate;
        selected.push({ bundleId, claimToken, expiresAt: record.expiresAt, packageSha256: record.packageSha256, sealedPackage: record.sealedPackage });
      }
      return { recipientId: auth.recipientId, bundles: selected, jobs: selected };
    });
  }

  function acknowledgeSigned(bundleId, bodyBytes, headers) {
    const id = bundleIdentifier(bundleId);
    const auth = authenticateSigned(bodyBytes, headers, `acknowledge:${id}`);
    return lock.withLock(`assurance-bundles:${auth.recipientId}`, () => {
      registerReplay(auth);
      maintenanceLocked(auth.recipientId);
      const input = parseStrictJson(bodyBytes, new Set(['claimToken', 'packageSha256', 'receipt']));
      const path = bundlePath(auth.recipientId, id);
      if (!existsSync(path)) throw new EvidenceValidationError('The assurance bundle was not found.', { bundleId: id });
      const record = readRecord(path, auth.recipientId, id);
      if (record.state === 'delivered') {
        if (input.receipt && deliveryReceipts.enabled) {
          deliveryReceipts.verifyAndRecord({
            tenantId: record.tenantId,
            recipientId: record.recipientId,
            bundleId: record.bundleId,
            packageSha256: record.packageSha256,
            claimedAt: record.claimedAt,
            ...strictReceipt(input.receipt)
          });
        }
        return publicRecord(record);
      }
      if (record.state !== 'claimed' || !record.claimExpiresAt || new Date(record.claimExpiresAt) <= now()) {
        throw new EvidenceConflictError('The assurance bundle claim is not active.', { bundleId: id });
      }
      const tokenHash = sha256(String(input.claimToken ?? ''));
      if (!safeEqual(tokenHash, record.claimTokenHash) || String(input.packageSha256 ?? '') !== record.packageSha256) {
        throw new EvidenceAssuranceBundleAuthenticationError('The assurance bundle claim proof is invalid.', { bundleId: id });
      }
      if (deliveryReceipts.required && !input.receipt) {
        throw new EvidenceValidationError('A recipient-signed delivery receipt is required.', { field: 'receipt' });
      }
      let receiptResult = null;
      if (input.receipt) {
        if (!deliveryReceipts.enabled) throw new EvidenceConflictError('Recipient-signed delivery receipts are disabled.');
        receiptResult = deliveryReceipts.verifyAndRecord({
          tenantId: record.tenantId,
          recipientId: record.recipientId,
          bundleId: record.bundleId,
          packageSha256: record.packageSha256,
          claimedAt: record.claimedAt,
          ...strictReceipt(input.receipt)
        });
      }
      record.state = 'delivered';
      record.deliveredAt = now().toISOString();
      record.claimTokenHash = null;
      record.claimExpiresAt = null;
      record.deliveryReceiptId = receiptResult?.receipt.receiptId ?? null;
      record.deliveryReceiptRecordHash = receiptResult?.receipt.recordHash ?? null;
      record.sealedPackage = null;
      replaceRecord(path, record, auth.recipientId, id);
      pruneLocked(auth.recipientId);
      return publicRecord(record);
    });
  }

  function tenantStatus(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    const rows = list(tenant, { limit: 5000 });
    const counts = { pending: 0, claimed: 0, delivered: 0, expired: 0, deliveredWithoutReceipt: 0 };
    for (const row of rows) {
      counts[row.state] = (counts[row.state] ?? 0) + 1;
      if (row.state === 'delivered' && !row.deliveryReceiptId) counts.deliveredWithoutReceipt += 1;
    }
    const receipts = deliveryReceipts.tenantStatus(tenant);
    const unavailable = deliveryReceipts.required && receipts.status !== 'ready';
    return {
      status: unavailable || counts.deliveredWithoutReceipt && deliveryReceipts.required ? 'unavailable' : counts.expired ? 'attention' : 'ready',
      enabled: true,
      required: isRequired,
      total: rows.length,
      ...counts,
      deliveryReceipts: receipts
    };
  }

  function health() {
    try {
      mkdirSync(root, { recursive: true, mode: 0o700 });
      const receipts = deliveryReceipts.health();
      return {
        status: deliveryReceipts.required && receipts.status !== 'ready' ? 'unavailable' : 'ready',
        enabled: true,
        required: isRequired,
        mode: 'recipient-pull-sealed-assurance-bundles',
        encryptedRecords: true,
        recipientEncryptedPackages: true,
        plaintextPersistence: false,
        arbitraryOutboundEgress: false,
        recipientCount: recipientMap.size,
        bundleTtlMinutes: ttlMs / 60_000,
        claimLeaseMs: leaseMs,
        maximumClaimBytes: claimBytes,
        deliveryReceipts: receipts,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: isRequired, error: error?.code ?? 'assurance_bundle_store_unavailable' };
    }
  }

  function authenticateSigned(bodyBytes, headers, operation) {
    const recipientId = identifier(header(headers, 'x-basitclaw-recipient-id'), 'recipientId');
    const keyId = keyIdentifier(header(headers, 'x-basitclaw-recipient-key-id'));
    const timestamp = isoDate(header(headers, 'x-basitclaw-recipient-timestamp'), 'timestamp');
    const nonce = nonceValue(header(headers, 'x-basitclaw-recipient-nonce'));
    const recipient = recipientMap.get(recipientId);
    const secret = recipient?.hmacKeys.get(keyId);
    if (!secret) throw new EvidenceAssuranceBundleAuthenticationError();
    if (Math.abs(now().getTime() - new Date(timestamp).getTime()) > skewMs) throw new EvidenceAssuranceBundleAuthenticationError('The assurance recipient timestamp is outside the accepted window.', { reason: 'timestamp_window' });
    const canonical = [recipientId, keyId, operation, timestamp, nonce, sha256(bodyBytes)].join('\n');
    const expected = createHmac('sha256', secret).update(canonical).digest();
    let supplied;
    try { supplied = strictBase64(header(headers, 'x-basitclaw-recipient-signature'), 'recipient signature'); }
    catch { throw new EvidenceAssuranceBundleAuthenticationError(); }
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new EvidenceAssuranceBundleAuthenticationError();
    return { recipientId, keyId, timestamp, nonce, replayId: sha256(canonical) };
  }

  function registerReplay(auth) {
    const path = replayPath(auth.recipientId, auth.replayId);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    try {
      const descriptor = openSync(path, 'wx', 0o600);
      try { writeFileSync(descriptor, `${auth.timestamp}\n`, 'utf8'); fsyncSync(descriptor); }
      finally { closeSync(descriptor); }
    } catch (error) {
      if (error?.code === 'EEXIST') throw new EvidenceAssuranceBundleAuthenticationError('The assurance recipient request was already used.', { reason: 'replay' });
      throw new EvidenceAssuranceBundleStoreError('The assurance recipient replay ledger is unavailable.', {}, error);
    }
  }

  function maintenanceLocked(recipientId) {
    const current = now();
    for (const filename of bundleNames(recipientId)) {
      const bundleId = filename.slice(0, -7);
      const path = bundlePath(recipientId, bundleId);
      const record = readRecord(path, recipientId, bundleId);
      let changed = false;
      if (record.state === 'claimed' && record.claimExpiresAt && new Date(record.claimExpiresAt) <= current) {
        record.state = 'pending'; record.claimTokenHash = null; record.claimedAt = null; record.claimExpiresAt = null; changed = true;
      }
      if ((record.state === 'pending' || record.state === 'claimed') && new Date(record.expiresAt) <= current) {
        record.state = 'expired'; record.claimTokenHash = null; record.claimExpiresAt = null; record.sealedPackage = null; changed = true;
      }
      if (changed) replaceRecord(path, record, recipientId, bundleId);
    }
    const replayDirectory = resolve(recipientRoot(recipientId), '.replay');
    if (existsSync(replayDirectory)) {
      for (const filename of readdirSync(replayDirectory)) {
        const path = resolve(replayDirectory, filename);
        try { if (current.getTime() - statSync(path).mtimeMs > DAY_MS) rmSync(path, { force: true }); } catch {}
      }
    }
  }
  function pruneLocked(recipientId) {
    const terminal = bundleNames(recipientId).map((filename) => {
      const id = filename.slice(0, -7); const path = bundlePath(recipientId, id); return { path, record: readRecord(path, recipientId, id) };
    }).filter((row) => ['delivered', 'expired'].includes(row.record.state))
      .sort((a, b) => String(a.record.deliveredAt ?? a.record.expiresAt).localeCompare(String(b.record.deliveredAt ?? b.record.expiresAt)));
    while (terminal.length > retained) rmSync(terminal.shift().path, { force: true });
  }

  function writeRecordExclusive(path, record, recipientId, bundleId) {
    const envelope = encryptEvidenceJson(record, encryption, recordAad(recipientId, bundleId));
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    let descriptor = null; let created = false; let committed = false;
    try {
      descriptor = openSync(path, 'wx', 0o600); created = true;
      writeFileSync(descriptor, `${JSON.stringify(envelope)}\n`, 'utf8'); fsyncSync(descriptor); closeSync(descriptor); descriptor = null; committed = true; fsyncDirectory(dirname(path));
    } catch (error) {
      if (descriptor !== null) try { closeSync(descriptor); } catch {}
      if (created && !committed) try { rmSync(path, { force: true }); } catch {}
      if (error?.code === 'EEXIST') throw new EvidenceIntegrityError('A conflicting assurance bundle already exists.', { bundleId });
      throw new EvidenceAssuranceBundleStoreError('The assurance bundle could not be committed.', { bundleId }, error);
    }
  }
  function replaceRecord(path, record, recipientId, bundleId) {
    const envelope = encryptEvidenceJson(record, encryption, recordAad(recipientId, bundleId));
    const temporary = `${path}.${randomUUID()}.tmp`; let descriptor = null;
    try {
      descriptor = openSync(temporary, 'wx', 0o600); writeFileSync(descriptor, `${JSON.stringify(envelope)}\n`, 'utf8'); fsyncSync(descriptor); closeSync(descriptor); descriptor = null; renameSync(temporary, path); fsyncDirectory(dirname(path));
    } catch (error) {
      if (descriptor !== null) try { closeSync(descriptor); } catch {}
      try { rmSync(temporary, { force: true }); } catch {}
      throw new EvidenceAssuranceBundleStoreError('The assurance bundle state could not be updated.', { bundleId }, error);
    }
  }
  function readRecord(path, recipientId, bundleId) {
    try {
      const record = decryptEvidenceJson(readEvidenceJson(path), encryption, recordAad(recipientId, bundleId), EvidenceIntegrityError);
      if (!record || record.format !== FORMAT || record.version !== 1 || record.bundleId !== bundleId || record.recipientId !== recipientId) throw new EvidenceIntegrityError('The assurance bundle record identity is invalid.', { bundleId });
      if (record.sealedPackage && sha256(stableStringify(record.sealedPackage)) !== record.packageSha256) throw new EvidenceIntegrityError('The assurance bundle package digest does not match its record.', { bundleId });
      return record;
    } catch (error) {
      if (error instanceof EvidenceIntegrityError) throw error;
      throw new EvidenceAssuranceBundleStoreError('The assurance bundle record is unreadable.', { bundleId }, error);
    }
  }

  function recipientRoot(recipientId) { const path = resolve(root, sha256(`recipient:${recipientId}`)); mkdirSync(path, { recursive: true, mode: 0o700 }); return path; }
  function bundlePath(recipientId, bundleId) { return resolve(recipientRoot(recipientId), `${bundleId}.bundle`); }
  function replayPath(recipientId, replayId) { return resolve(recipientRoot(recipientId), '.replay', `${replayId}.nonce`); }
  function bundleNames(recipientId) { return readdirSync(recipientRoot(recipientId)).filter((name) => name.endsWith('.bundle') && BUNDLE_ID.test(name.slice(0, -7))).sort(); }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    required: isRequired,
    bundleTtlMs: ttlMs,
    queue,
    list,
    claimSigned,
    acknowledgeSigned,
    tenantStatus,
    health,
    recipientIds: () => [...recipientMap.keys()],
    deliveryReceiptStore: deliveryReceipts
  });
}

export function createEvidenceAssuranceBundleStoreFromEnvironment({ env = process.env } = {}) {
  const mode = envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MODE) ?? 'disabled';
  const required = parseBoolean(envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_REQUIRED) ?? false);
  if (mode === 'disabled') return createEvidenceAssuranceBundleStore({ mode, required });
  const keysRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_KEYS);
  const primaryKeyId = envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_PRIMARY_KEY_ID);
  const recipientsRaw = envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENTS);
  if (!keysRaw) throw new EvidenceAssuranceBundleStoreError('Dedicated assurance bundle encryption keys are required.', { reason: 'missing_bundle_keys' });
  if (!primaryKeyId) throw new EvidenceAssuranceBundleStoreError('The assurance bundle primary key ID is required.', { reason: 'missing_bundle_primary_key_id' });
  if (!recipientsRaw) throw new EvidenceAssuranceBundleStoreError('Assurance recipient configuration is required.', { reason: 'missing_recipients' });
  try {
    const deliveryReceipts = createEvidenceAssuranceReceiptStoreFromEnvironment({ env });
    return createEvidenceAssuranceBundleStore({
      mode, required,
      directory: envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_DIR),
      encryptionKeys: JSON.parse(keysRaw),
      encryptionPrimaryKeyId: primaryKeyId,
      recipients: JSON.parse(recipientsRaw),
      deliveryReceipts,
      bundleTtlMinutes: envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_TTL_MINUTES) ?? 1440,
      claimLeaseMs: envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_CLAIM_LEASE_MS) ?? DEFAULT_CLAIM_LEASE_MS,
      maximumClaimBytes: envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MAX_CLAIM_BYTES) ?? 25_000_000,
      retention: envValue(env.WORKFORCE_AUDIT_ASSURANCE_BUNDLE_RETENTION) ?? 10_000,
      clockSkewSeconds: envValue(env.WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_CLOCK_SKEW_SECONDS) ?? 300
    });
  } catch (error) {
    if (error instanceof EvidenceAssuranceBundleStoreError) throw error;
    throw new EvidenceAssuranceBundleStoreError('Assurance bundle configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function sealForRecipient(payload, recipient, bundleId) {
  const recipientPublicKeyId = recipient.primaryPublicKeyId;
  const publicKey = recipient.publicKeys.get(recipientPublicKeyId);
  const plaintext = Buffer.from(stableStringify(payload));
  const contentKey = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from(`basitclaw:assurance-bundle:${bundleId}:${recipientPublicKeyId}`);
  const cipher = createCipheriv('aes-256-gcm', contentKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  const wrappedKey = publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, contentKey);
  contentKey.fill(0);
  return {
    format: SEALED_FORMAT,
    version: 1,
    algorithm: 'RSA-OAEP-SHA256+A256GCM',
    recipientPublicKeyId,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    aad: aad.toString('base64'),
    wrappedKey: wrappedKey.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    plaintextSha256: sha256(plaintext)
  };
}
function validateQueueInput(input, recipients, now, ttlMs) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid assurance bundle request is required.');
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = evidenceIdentifier(input.evidenceId);
  const evidenceVersion = integer(input.evidenceVersion, 'evidenceVersion', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  const recipientId = identifier(input.recipientId, 'recipientId');
  if (!recipients.has(recipientId)) throw new EvidenceValidationError('The requested assurance recipient is not configured.', { field: 'recipientId' });
  const requestedBy = identifier(input.requestedBy, 'requestedBy');
  const purpose = cleanText(input.purpose, 'purpose', 10, 500);
  if (!input.manifest || typeof input.manifest !== 'object' || Array.isArray(input.manifest)) throw new EvidenceValidationError('A valid assurance bundle manifest is required.');
  if (!input.evidence || typeof input.evidence !== 'object' || Array.isArray(input.evidence)) throw new EvidenceValidationError('A valid assurance bundle payload is required.');
  const created = now();
  return { tenantId, evidenceId, evidenceVersion, contentSha256, recipientId, requestedBy, purpose, manifest: structuredClone(input.manifest), evidence: structuredClone(input.evidence), createdAt: created.toISOString(), expiresAt: new Date(created.getTime() + ttlMs).toISOString() };
}
function parseRecipients(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Assurance recipients must be an object.');
  const entries = Object.entries(raw);
  if (entries.length > 100) throw new TypeError('No more than 100 assurance recipients are supported.');
  const result = new Map();
  for (const [recipientId, value] of entries) {
    identifier(recipientId, 'recipientId');
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`Assurance recipient ${recipientId} must be an object.`);
    const hmacEntries = Object.entries(value.keys ?? {});
    if (!hmacEntries.length) throw new TypeError(`Assurance recipient ${recipientId} needs at least one HMAC key.`);
    const hmacKeys = new Map(hmacEntries.map(([keyId, encoded]) => {
      keyIdentifier(keyId);
      const secret = strictBase64(encoded, `recipient secret ${recipientId}/${keyId}`);
      if (secret.length < 32 || secret.length > 128) throw new TypeError(`Assurance recipient ${recipientId} HMAC keys must decode to 32 to 128 bytes.`);
      return [keyId, secret];
    }));
    const publicEntries = Object.entries(value.publicKeys ?? {});
    if (!publicEntries.length) throw new TypeError(`Assurance recipient ${recipientId} needs at least one RSA public key.`);
    const publicKeys = new Map(publicEntries.map(([keyId, pem]) => {
      keyIdentifier(keyId);
      const key = createPublicKey(String(pem));
      if (key.asymmetricKeyType !== 'rsa') throw new TypeError(`Assurance recipient ${recipientId} public key ${keyId} must be RSA.`);
      if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Assurance recipient ${recipientId} RSA key ${keyId} must be at least 2048 bits.`);
      return [keyId, key];
    }));
    const primaryPublicKeyId = keyIdentifier(value.primaryPublicKeyId ?? publicEntries[0][0]);
    if (!publicKeys.has(primaryPublicKeyId)) throw new TypeError(`Assurance recipient ${recipientId} primary public key is unavailable.`);
    result.set(recipientId, Object.freeze({ hmacKeys, publicKeys, primaryPublicKeyId }));
  }
  return result;
}
function strictReceipt(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('receipt must be an object.', { field: 'receipt' });
  const allowed = new Set(['receivedAt', 'keyId', 'signature']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Unsupported delivery receipt field ${key}.`, { field: `receipt.${key}` });
  return { receivedAt: input.receivedAt, keyId: input.keyId, signature: input.signature };
}
function parseStrictJson(bytes, allowed) {
  let input;
  try { input = JSON.parse(Buffer.from(bytes).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('The assurance recipient request must contain valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('The assurance recipient request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Unsupported assurance recipient field ${key}.`, { field: key });
  return input;
}
function bundleIdFor(input) { return `ASB-${sha256([input.tenantId, input.evidenceId, String(input.evidenceVersion), input.contentSha256, input.recipientId, input.manifest.bundleDigest].join('|')).slice(0, 32)}`; }
function assertSameBundle(record, input) { if (record.tenantId !== input.tenantId || record.evidenceId !== input.evidenceId || record.evidenceVersion !== input.evidenceVersion || record.contentSha256 !== input.contentSha256 || record.recipientId !== input.recipientId) throw new EvidenceIntegrityError('An existing assurance bundle conflicts with this request.', { bundleId: record.bundleId }); }
function publicRecord(record) { return { bundleId: record.bundleId, evidenceId: record.evidenceId, evidenceVersion: record.evidenceVersion, contentSha256: record.contentSha256, recipientId: record.recipientId, recipientPublicKeyId: record.recipientPublicKeyId, purpose: record.purpose, requestedBy: record.requestedBy, createdAt: record.createdAt, expiresAt: record.expiresAt, state: record.state, claimedAt: record.claimedAt, claimExpiresAt: record.claimExpiresAt, deliveredAt: record.deliveredAt, packageSha256: record.packageSha256, deliveryReceiptId: record.deliveryReceiptId ?? null, deliveryReceiptRecordHash: record.deliveryReceiptRecordHash ?? null }; }
function recordAad(recipientId, bundleId) { return `basitclaw:assurance-bundle-record:${recipientId}:${bundleId}`; }
function fsyncDirectory(path) { const descriptor = openSync(path, 'r'); try { fsyncSync(descriptor); } finally { closeSync(descriptor); } }
function safeEqual(left, right) { if (!left || !right) return false; const a = Buffer.from(left); const b = Buffer.from(right); return a.length === b.length && timingSafeEqual(a, b); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function header(headers, name) { const value = headers?.[name] ?? headers?.[name.toLowerCase()]; return Array.isArray(value) ? value[0] : String(value ?? ''); }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function keyIdentifier(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(text)) throw new EvidenceValidationError('keyId is invalid.', { field: 'keyId' }); return text; }
function bundleIdentifier(value) { const text = String(value ?? ''); if (!BUNDLE_ID.test(text)) throw new EvidenceValidationError('bundleId is invalid.', { field: 'bundleId' }); return text; }
function evidenceIdentifier(value) { const text = String(value ?? ''); if (!EVIDENCE_ID.test(text)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return text; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!/^[a-f0-9]{64}$/.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function nonceValue(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9._:-]{16,191}$/.test(text)) throw new EvidenceAssuranceBundleAuthenticationError(); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function cleanText(value, field, min, max) { const text = String(value ?? '').trim(); if (text.length < min || text.length > max) throw new EvidenceValidationError(`${field} must contain ${min} to ${max} characters.`, { field }); return text; }
function integer(value, field, min, max) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < min || parsed > max) throw new EvidenceValidationError(`${field} must be an integer from ${min} to ${max}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be true or false.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment values must be true or false.'); }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function disabledStore() { const status = Object.freeze({ status: 'disabled', enabled: false, required: false, mode: 'disabled' }); return Object.freeze({ mode: 'disabled', enabled: false, required: false, bundleTtlMs: 0, queue() { throw new EvidenceConflictError('Assurance bundle delivery is disabled.'); }, list() { return []; }, claimSigned() { throw new EvidenceConflictError('Assurance bundle delivery is disabled.'); }, acknowledgeSigned() { throw new EvidenceConflictError('Assurance bundle delivery is disabled.'); }, tenantStatus() { return status; }, health() { return status; }, recipientIds() { return []; }, deliveryReceiptStore: createEvidenceAssuranceReceiptStore({ mode: 'disabled' }) }); }
