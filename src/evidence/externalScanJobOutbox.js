import {
  constants,
  createCipheriv,
  createHash,
  createHmac,
  createPublicKey,
  publicEncrypt,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
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
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import { ExternalScanAuthenticationError } from './externalScanAttestationRegistry.js';

const RECORD_FORMAT = 'basitclaw-external-scan-job';
const PACKAGE_FORMAT = 'basitclaw-external-scan-sealed-package';
const PAYLOAD_FORMAT = 'basitclaw-external-scan-job-payload';
const MODES = new Set(['disabled', 'pull']);
const STATES = ['pending', 'inflight', 'delivered', 'completed', 'dead-letter'];
const JOB_ID = /^SCNJOB-[a-f0-9]{32}$/;
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const NONCE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{15,127}$/;

export class ExternalScanJobStoreError extends EvidenceStoreError {
  constructor(message = 'The external scan job outbox is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'ExternalScanJobStoreError';
    this.code = 'EXTERNAL_SCAN_JOB_STORE_UNAVAILABLE';
  }
}

export function createExternalScanJobOutbox({
  mode = 'disabled',
  required = false,
  directory,
  evidenceKeys,
  evidencePrimaryKeyId,
  providers = {},
  jobTtlMinutes = 1440,
  claimLeaseMs = 300_000,
  maxAttempts = 5,
  completedRetention = 10_000,
  deadLetterRetention = 2_000,
  clockSkewSeconds = 300,
  now = () => new Date(),
  mutex = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required external scan job delivery cannot be disabled.');
    return disabledOutbox();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An external scan job directory is required.');

  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(evidenceKeys, evidencePrimaryKeyId);
  const providerMap = parseProviders(providers);
  const ttlMinutes = integer(jobTtlMinutes, 'jobTtlMinutes', 1, 10_080);
  const leaseMs = integer(claimLeaseMs, 'claimLeaseMs', 1_000, 3_600_000);
  const attemptsLimit = integer(maxAttempts, 'maxAttempts', 1, 100);
  const completedLimit = integer(completedRetention, 'completedRetention', 100, 1_000_000);
  const deadLimit = integer(deadLetterRetention, 'deadLetterRetention', 1, 100_000);
  const skewSeconds = integer(clockSkewSeconds, 'clockSkewSeconds', 1, 3600);
  const stateDirectories = Object.fromEntries(STATES.map((state) => [state, resolve(root, state)]));
  const replayDirectory = resolve(root, 'request-replays');
  for (const path of [root, replayDirectory, ...Object.values(stateDirectories)]) ensureDirectory(path);
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });

  if (![...providerMap.values()].some((provider) => provider.hmacKeys.size && provider.deliveryKeys.size)) {
    throw new TypeError('At least one scanner provider must contain both HMAC keys and RSA publicKeys.');
  }

  function queue(contentRecord, providerId, { actor } = {}) {
    const content = validateContentRecord(contentRecord);
    const provider = providerFor(providerMap, providerId);
    if (!provider.hmacKeys.size) throw new EvidenceConflictError('The selected scanner provider has no HMAC request keys.', { providerId });
    const delivery = latestDeliveryKey(provider, providerId);
    const queuedBy = identifier(actor, 'actor');
    const jobId = jobIdFor(content, providerId);

    return lock.withLock('external-scan-job-outbox', () => {
      recoverStaleLocked();
      const existing = locate(jobId);
      if (existing) {
        const record = readRecord(existing.path);
        return { queued: false, duplicate: true, job: publicJob(record, decryptManagement(record)) };
      }
      const createdAt = now().toISOString();
      const expiresAt = new Date(now().getTime() + ttlMinutes * 60_000).toISOString();
      const management = {
        tenantId: content.tenantId,
        evidenceId: content.evidenceId,
        evidenceVersion: content.version,
        contentSha256: content.contentSha256,
        sizeBytes: content.sizeBytes,
        filename: content.filename,
        mediaType: content.mediaType,
        queuedBy
      };
      const sealedPackage = sealPackage({
        content,
        providerId,
        deliveryKeyId: delivery.keyId,
        publicKey: delivery.publicKey,
        jobId,
        createdAt,
        expiresAt
      });
      const record = {
        format: RECORD_FORMAT,
        version: 1,
        jobId,
        providerId,
        deliveryKeyId: delivery.keyId,
        state: 'pending',
        createdAt,
        updatedAt: createdAt,
        expiresAt,
        attempts: 0,
        nextAttemptAt: createdAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        deliveredAt: null,
        completedAt: null,
        deadLetteredAt: null,
        result: null,
        packageSha256: packageHash(sealedPackage),
        package: sealedPackage,
        management: encryptEvidenceJson(management, keyring, managementAad(jobId))
      };
      writeRecord(resolve(stateDirectories.pending, `${jobId}.json`), record);
      return { queued: true, duplicate: false, job: publicJob(record, management) };
    });
  }

  function claimSigned(bodyBuffer, headers = {}) {
    const auth = authenticate(bodyBuffer, headers);
    const input = parseStrictJson(bodyBuffer, new Set(['limit']));
    const limit = integer(input.limit ?? 1, 'limit', 1, 25);
    return lock.withLock('external-scan-job-outbox', () => {
      consumeReplayLocked(auth);
      recoverStaleLocked();
      const claimed = [];
      for (const filename of jsonNames(stateDirectories.pending)) {
        if (claimed.length >= limit) break;
        const source = resolve(stateDirectories.pending, filename);
        const record = readRecord(source);
        if (record.providerId !== auth.providerId) continue;
        if (new Date(record.nextAttemptAt).getTime() > now().getTime()) continue;
        if (new Date(record.expiresAt).getTime() <= now().getTime()) {
          moveToDeadLocked(source, record, 'job_expired');
          continue;
        }
        if (!record.package || packageHash(record.package) !== record.packageSha256) {
          moveToDeadLocked(source, record, 'sealed_package_invalid');
          continue;
        }
        const claimToken = randomUUID();
        const claimedAt = now().toISOString();
        const next = {
          ...record,
          state: 'inflight',
          updatedAt: claimedAt,
          attempts: record.attempts + 1,
          claimToken,
          claimedAt,
          claimExpiresAt: new Date(now().getTime() + leaseMs).toISOString()
        };
        writeAndMove(source, resolve(stateDirectories.inflight, filename), next);
        claimed.push({ jobId: next.jobId, claimToken, claimExpiresAt: next.claimExpiresAt, package: structuredClone(next.package) });
      }
      return { providerId: auth.providerId, jobs: claimed };
    });
  }

  function acknowledgeSigned(jobId, bodyBuffer, headers = {}) {
    const auth = authenticate(bodyBuffer, headers);
    const input = parseStrictJson(bodyBuffer, new Set(['claimToken']));
    const claimToken = identifier(input.claimToken, 'claimToken');
    return lock.withLock('external-scan-job-outbox', () => {
      consumeReplayLocked(auth);
      const id = safeJobId(jobId);
      const source = resolve(stateDirectories.inflight, `${id}.json`);
      const record = readOwnedClaim(source, auth.providerId, claimToken);
      const deliveredAt = now().toISOString();
      const next = {
        ...record,
        state: 'delivered',
        updatedAt: deliveredAt,
        deliveredAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        package: null,
        result: { delivery: 'acknowledged' }
      };
      writeAndMove(source, resolve(stateDirectories.delivered, `${id}.json`), next);
      pruneLocked(stateDirectories.delivered, completedLimit);
      return publicJob(next, decryptManagement(next));
    });
  }

  function failSigned(jobId, bodyBuffer, headers = {}) {
    const auth = authenticate(bodyBuffer, headers);
    const input = parseStrictJson(bodyBuffer, new Set(['claimToken', 'retryable', 'reasonCode']));
    const claimToken = identifier(input.claimToken, 'claimToken');
    const retryable = booleanValue(input.retryable, 'retryable');
    const reasonCode = safeReasonCode(input.reasonCode);
    return lock.withLock('external-scan-job-outbox', () => {
      consumeReplayLocked(auth);
      const id = safeJobId(jobId);
      const source = resolve(stateDirectories.inflight, `${id}.json`);
      const record = readOwnedClaim(source, auth.providerId, claimToken);
      if (retryable && record.attempts < attemptsLimit && record.package) {
        const retryAt = now().toISOString();
        const next = {
          ...record,
          state: 'pending',
          updatedAt: retryAt,
          nextAttemptAt: retryAt,
          claimToken: null,
          claimedAt: null,
          claimExpiresAt: null,
          result: { delivery: 'retry', reasonCode }
        };
        writeAndMove(source, resolve(stateDirectories.pending, `${id}.json`), next);
        return publicJob(next, decryptManagement(next));
      }
      const dead = moveToDeadLocked(source, record, reasonCode);
      return publicJob(dead, decryptManagement(dead));
    });
  }

  function completeFromAttestation(attestation) {
    if (!attestation?.tenantId || !attestation?.evidenceId || !attestation?.providerId) return { matched: false };
    const jobId = jobIdFor({
      tenantId: attestation.tenantId,
      evidenceId: attestation.evidenceId,
      version: attestation.version,
      contentSha256: attestation.contentSha256
    }, attestation.providerId);
    return lock.withLock('external-scan-job-outbox', () => {
      const located = locate(jobId);
      if (!located) return { matched: false, jobId };
      const record = readRecord(located.path);
      const management = decryptManagement(record);
      if (management.tenantId !== attestation.tenantId
          || management.evidenceId !== attestation.evidenceId
          || management.evidenceVersion !== attestation.version
          || management.contentSha256 !== attestation.contentSha256
          || record.providerId !== attestation.providerId) {
        throw new EvidenceIntegrityError('External scan attestation does not match its sealed delivery job.', { jobId });
      }
      if (record.state === 'completed') return { matched: true, duplicate: true, job: publicJob(record, management) };
      const completedAt = now().toISOString();
      const next = {
        ...record,
        state: 'completed',
        updatedAt: completedAt,
        completedAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        package: null,
        result: {
          attestationId: attestation.attestationId,
          receiptId: attestation.receiptId,
          verdict: attestation.verdict,
          scannedAt: attestation.scannedAt
        }
      };
      writeAndMove(located.path, resolve(stateDirectories.completed, `${jobId}.json`), next);
      pruneLocked(stateDirectories.completed, completedLimit);
      return { matched: true, duplicate: false, job: publicJob(next, management) };
    });
  }

  function list(tenantId, { evidenceId = null, limit = 100 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceId === null ? null : safeEvidenceId(evidenceId);
    return lock.withLock('external-scan-job-outbox', () => {
      recoverStaleLocked();
      const rows = [];
      for (const state of STATES) {
        for (const filename of jsonNames(stateDirectories[state])) {
          const record = readRecord(resolve(stateDirectories[state], filename));
          const management = decryptManagement(record);
          if (management.tenantId !== tenant || (evidence && management.evidenceId !== evidence)) continue;
          rows.push(publicJob(record, management));
        }
      }
      return rows.sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, integer(limit, 'limit', 1, 5000));
    });
  }

  function latest(tenantId, evidenceId, version = null) {
    const rows = list(tenantId, { evidenceId, limit: 5000 });
    return rows.find((job) => version === null || job.evidenceVersion === Number(version)) ?? null;
  }

  function tenantStatus(tenantId) {
    const jobs = list(tenantId, { limit: 5000 });
    const count = (state) => jobs.filter((job) => job.state === state).length;
    const deadLetters = count('dead-letter');
    const pending = count('pending');
    const inflight = count('inflight');
    return {
      status: deadLetters || pending || inflight ? 'attention' : 'ready',
      enabled: true,
      required: isRequired,
      mode: selectedMode,
      total: jobs.length,
      pending,
      inflight,
      delivered: count('delivered'),
      completed: count('completed'),
      deadLetters
    };
  }

  function verify(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    return lock.withLock('external-scan-job-outbox', () => {
      let checkedJobs = 0;
      for (const state of STATES) {
        for (const filename of jsonNames(stateDirectories[state])) {
          const record = readRecord(resolve(stateDirectories[state], filename));
          const management = decryptManagement(record);
          if (management.tenantId !== tenant) continue;
          if (record.package && packageHash(record.package) !== record.packageSha256) {
            throw new EvidenceIntegrityError('A sealed external scan package checksum is invalid.', { jobId: record.jobId });
          }
          checkedJobs += 1;
        }
      }
      return { valid: true, tenantId: tenant, checkedJobs };
    });
  }

  function health() {
    try {
      for (const path of [root, replayDirectory, ...Object.values(stateDirectories)]) ensureDirectory(path);
      const counts = Object.fromEntries(STATES.map((state) => [state, jsonNames(stateDirectories[state]).length]));
      return {
        status: counts['dead-letter'] ? 'degraded' : 'ready',
        enabled: true,
        required: isRequired,
        mode: selectedMode,
        durable: true,
        distributed: true,
        plaintextQueued: false,
        publicKeySealed: true,
        requestReplayProtected: true,
        providerCount: providerMap.size,
        jobTtlMinutes: ttlMinutes,
        claimLeaseMs: leaseMs,
        maxAttempts: attemptsLimit,
        counts,
        mutex: lock.health()
      };
    } catch (error) {
      return { status: 'unavailable', enabled: true, required: isRequired, mode: selectedMode, error: error?.code ?? 'external_scan_job_store_unavailable' };
    }
  }

  function locate(jobId) {
    for (const state of STATES) {
      const path = resolve(stateDirectories[state], `${jobId}.json`);
      if (existsSync(path)) return { state, path };
    }
    return null;
  }

  function authenticate(bodyBuffer, headers = {}) {
    if (!Buffer.isBuffer(bodyBuffer)) throw new TypeError('Scanner delivery request body must be a Buffer.');
    const providerId = header(headers, 'x-basitclaw-scan-provider');
    const keyId = header(headers, 'x-basitclaw-scan-key-id');
    const timestamp = header(headers, 'x-basitclaw-scan-timestamp');
    const nonce = header(headers, 'x-basitclaw-scan-nonce');
    const signature = header(headers, 'x-basitclaw-scan-signature').toLowerCase();
    const provider = providerMap.get(providerId);
    const secret = provider?.hmacKeys.get(keyId);
    if (!provider || !secret || !NONCE.test(nonce) || !HASH.test(signature)) throw new ExternalScanAuthenticationError();
    const signedAt = validDate(timestamp, 'timestamp');
    const distanceSeconds = Math.abs(now().getTime() - signedAt.getTime()) / 1000;
    if (distanceSeconds > skewSeconds) throw new ExternalScanAuthenticationError('External scanner timestamp is outside the allowed clock-skew window.', { reason: 'timestamp_out_of_window' });
    const bodySha256 = sha256(bodyBuffer);
    const canonical = `${providerId}\n${keyId}\n${signedAt.toISOString()}\n${nonce}\n${bodySha256}`;
    const expected = createHmac('sha256', secret).update(canonical).digest();
    const supplied = Buffer.from(signature, 'hex');
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new ExternalScanAuthenticationError();
    return {
      providerId,
      keyId,
      signedAt: signedAt.toISOString(),
      nonce,
      replayId: createHash('sha256').update(canonical).digest('hex')
    };
  }

  function consumeReplayLocked(authentication) {
    pruneReplaysLocked();
    const path = resolve(replayDirectory, `${authentication.replayId}.json`);
    if (existsSync(path)) throw new ExternalScanAuthenticationError('External scanner request replay was rejected.', { reason: 'replay_detected' });
    atomicWriteEvidenceJson(path, {
      version: 1,
      replayId: authentication.replayId,
      providerId: authentication.providerId,
      keyId: authentication.keyId,
      acceptedAt: now().toISOString(),
      expiresAt: new Date(now().getTime() + skewSeconds * 2_000).toISOString()
    });
  }

  function pruneReplaysLocked() {
    const current = now().getTime();
    for (const filename of readdirSync(replayDirectory).filter((name) => /^[a-f0-9]{64}\.json$/.test(name))) {
      const path = resolve(replayDirectory, filename);
      try {
        const replay = readEvidenceJson(path);
        if (new Date(replay.expiresAt).getTime() <= current) rmSync(path, { force: true });
      } catch {
        rmSync(path, { force: true });
      }
    }
  }

  function recoverStaleLocked() {
    for (const filename of jsonNames(stateDirectories.inflight)) {
      const source = resolve(stateDirectories.inflight, filename);
      const record = readRecord(source);
      if (new Date(record.claimExpiresAt ?? 0).getTime() > now().getTime()) continue;
      if (record.package && record.attempts < attemptsLimit && new Date(record.expiresAt).getTime() > now().getTime()) {
        const recoveredAt = now().toISOString();
        const next = {
          ...record,
          state: 'pending',
          updatedAt: recoveredAt,
          nextAttemptAt: recoveredAt,
          claimToken: null,
          claimedAt: null,
          claimExpiresAt: null,
          result: { delivery: 'claim_recovered' }
        };
        writeAndMove(source, resolve(stateDirectories.pending, filename), next);
      } else {
        moveToDeadLocked(source, record, 'claim_expired');
      }
    }
  }

  function moveToDeadLocked(source, record, reasonCode) {
    const deadAt = now().toISOString();
    const next = {
      ...record,
      state: 'dead-letter',
      updatedAt: deadAt,
      deadLetteredAt: deadAt,
      claimToken: null,
      claimedAt: null,
      claimExpiresAt: null,
      package: null,
      result: { delivery: 'dead-letter', reasonCode: safeReasonCode(reasonCode) }
    };
    writeAndMove(source, resolve(stateDirectories['dead-letter'], `${record.jobId}.json`), next);
    pruneLocked(stateDirectories['dead-letter'], deadLimit);
    return next;
  }

  function decryptManagement(record) {
    return decryptEvidenceJson(record.management, keyring, managementAad(record.jobId), EvidenceIntegrityError);
  }

  return Object.freeze({
    enabled: true,
    required: isRequired,
    mode: selectedMode,
    queue,
    claimSigned,
    acknowledgeSigned,
    failSigned,
    completeFromAttestation,
    list,
    latest,
    tenantStatus,
    verify,
    health,
    directory: root
  });
}

export function createExternalScanJobOutboxFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_MODE) ?? 'disabled';
  const required = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_REQUIRED) ?? false);
  if (mode === 'disabled') return createExternalScanJobOutbox({ mode, required });
  if (!evidenceRegistry?.enabled || !evidenceRegistry.directory) throw new ExternalScanJobStoreError('Scanner delivery requires enabled evidence custody.');
  let evidenceKeys;
  let providers;
  try {
    evidenceKeys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
    providers = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS));
  } catch (error) {
    throw new ExternalScanJobStoreError('Scanner delivery configuration JSON is invalid.', {}, error);
  }
  try {
    return createExternalScanJobOutbox({
      mode,
      required,
      directory: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_DIR) ?? resolve(evidenceRegistry.directory, '.external-scan-jobs'),
      evidenceKeys,
      evidencePrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      providers,
      jobTtlMinutes: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_JOB_TTL_MINUTES) ?? 1440,
      claimLeaseMs: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_CLAIM_LEASE_MS) ?? 300_000,
      maxAttempts: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_MAX_DELIVERY_ATTEMPTS) ?? 5,
      completedRetention: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_COMPLETED_RETENTION) ?? 10_000,
      deadLetterRetention: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DEAD_LETTER_RETENTION) ?? 2_000,
      clockSkewSeconds: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_CLOCK_SKEW_SECONDS) ?? 300
    });
  } catch (error) {
    if (error instanceof ExternalScanJobStoreError) throw error;
    throw new ExternalScanJobStoreError('Scanner delivery configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

function sealPackage({ content, providerId, deliveryKeyId, publicKey, jobId, createdAt, expiresAt }) {
  const payload = Buffer.from(JSON.stringify({
    format: PAYLOAD_FORMAT,
    version: 1,
    jobId,
    tenantId: content.tenantId,
    evidenceId: content.evidenceId,
    evidenceVersion: content.version,
    contentSha256: content.contentSha256,
    filename: content.filename,
    mediaType: content.mediaType,
    sizeBytes: content.sizeBytes,
    createdAt,
    expiresAt,
    contentBase64: content.content.toString('base64')
  }));
  const key = randomBytes(32);
  const iv = randomBytes(12);
  const aad = Buffer.from(packageAad(jobId, providerId, deliveryKeyId));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const wrappedKey = publicEncrypt({ key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  return {
    format: PACKAGE_FORMAT,
    version: 1,
    algorithm: 'rsa-oaep-sha256+aes-256-gcm',
    jobId,
    providerId,
    deliveryKeyId,
    createdAt,
    expiresAt,
    aad: aad.toString('base64'),
    wrappedKey: wrappedKey.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    ciphertextSha256: sha256(ciphertext)
  };
}

function parseProviders(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('External scanner providers must be an object.');
  const providers = new Map();
  for (const [providerId, provider] of Object.entries(input)) {
    identifier(providerId, 'providerId');
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`External scanner provider ${providerId} must be an object.`);
    const hmacKeys = new Map();
    for (const [keyId, encoded] of Object.entries(provider.keys ?? {})) {
      identifier(keyId, 'keyId');
      const secret = strictBase64(encoded, `external scanner key ${providerId}/${keyId}`);
      if (secret.length < 32 || secret.length > 128) throw new TypeError(`External scanner key ${providerId}/${keyId} must decode to 32 to 128 bytes.`);
      hmacKeys.set(keyId, secret);
    }
    const deliveryKeys = new Map();
    for (const [keyId, pem] of Object.entries(provider.publicKeys ?? {})) {
      identifier(keyId, 'deliveryKeyId');
      const key = createPublicKey(String(pem));
      if (key.asymmetricKeyType !== 'rsa') throw new TypeError(`External scanner public key ${providerId}/${keyId} must be an RSA encryption key.`);
      const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
      if (bits < 2048) throw new TypeError(`External scanner public key ${providerId}/${keyId} must be at least 2048 bits.`);
      deliveryKeys.set(keyId, key);
    }
    providers.set(providerId, { hmacKeys, deliveryKeys });
  }
  return providers;
}

function latestDeliveryKey(provider, providerId) {
  const entry = [...provider.deliveryKeys.entries()].at(-1);
  if (!entry) throw new EvidenceConflictError('The selected scanner provider has no approved delivery public key.', { providerId });
  return { keyId: entry[0], publicKey: entry[1] };
}
function providerFor(providers, providerId) {
  const id = identifier(providerId, 'providerId');
  const provider = providers.get(id);
  if (!provider) throw new EvidenceValidationError('providerId is not an approved external scanner provider.', { field: 'providerId' });
  return provider;
}
function jobIdFor(content, providerId) {
  const stable = `${content.tenantId}\u0000${content.evidenceId}\u0000${content.version}\u0000${providerId}\u0000${content.contentSha256}`;
  return `SCNJOB-${createHash('sha256').update(stable).digest('hex').slice(0, 32)}`;
}
function validateContentRecord(input) {
  if (!input || typeof input !== 'object' || !Buffer.isBuffer(input.content)) throw new EvidenceValidationError('A verified evidence content record is required.');
  const tenantId = identifier(input.tenantId, 'tenantId');
  const evidenceId = safeEvidenceId(input.evidenceId);
  const version = integer(input.version, 'version', 1, 1_000_000);
  const contentSha256 = hashValue(input.contentSha256, 'contentSha256');
  if (sha256(input.content) !== contentSha256 || input.content.length !== Number(input.sizeBytes)) throw new EvidenceIntegrityError('Verified scanner delivery content no longer matches its immutable digest.', { evidenceId, version });
  return { ...input, tenantId, evidenceId, version, contentSha256, sizeBytes: input.content.length };
}
function readOwnedClaim(path, providerId, claimToken) {
  const record = readRecord(path);
  if (record.state !== 'inflight' || record.providerId !== providerId || record.claimToken !== claimToken) {
    throw new EvidenceConflictError('The external scan delivery claim is no longer owned.', { jobId: record.jobId });
  }
  return record;
}
function readRecord(path) {
  if (!existsSync(path)) throw new EvidenceConflictError('The external scan job was not found or is no longer claimable.');
  let record;
  try { record = readEvidenceJson(path); }
  catch (error) { throw new ExternalScanJobStoreError('An external scan job record is unreadable.', {}, error); }
  validateRecord(record);
  return record;
}
function validateRecord(record) {
  if (!record || record.format !== RECORD_FORMAT || record.version !== 1 || !JOB_ID.test(record.jobId)
      || !STATES.includes(record.state) || !record.management || !HASH.test(record.packageSha256)) {
    throw new EvidenceIntegrityError('An external scan job record is invalid.', { jobId: record?.jobId ?? null });
  }
}
function writeRecord(path, record) { validateRecord(record); atomicWriteEvidenceJson(path, record); }
function writeAndMove(source, target, record) { writeRecord(target, record); if (source !== target) rmSync(source, { force: true }); }
function publicJob(record, management) {
  return {
    jobId: record.jobId,
    providerId: record.providerId,
    deliveryKeyId: record.deliveryKeyId,
    state: record.state,
    evidenceId: management.evidenceId,
    evidenceVersion: management.evidenceVersion,
    contentSha256: management.contentSha256,
    sizeBytes: management.sizeBytes,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    expiresAt: record.expiresAt,
    attempts: record.attempts,
    deliveredAt: record.deliveredAt,
    completedAt: record.completedAt,
    deadLetteredAt: record.deadLetteredAt,
    result: record.result ? structuredClone(record.result) : null
  };
}
function packageHash(value) { return sha256(Buffer.from(JSON.stringify(value))); }
function managementAad(jobId) { return `basitclaw:external-scan-job-management:${jobId}`; }
function packageAad(jobId, providerId, keyId) { return `basitclaw:external-scan-job:${jobId}:${providerId}:${keyId}`; }
function ensureDirectory(path) { mkdirSync(path, { recursive: true, mode: 0o700 }); }
function jsonNames(directory) { return readdirSync(directory).filter((name) => /^SCNJOB-[a-f0-9]{32}\.json$/.test(name)).sort(); }
function pruneLocked(directory, limit) { const names = jsonNames(directory); for (const name of names.slice(0, Math.max(0, names.length - limit))) rmSync(resolve(directory, name), { force: true }); }
function parseStrictJson(bodyBuffer, allowed) {
  let value;
  try { value = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Scanner delivery request body must be valid JSON.', { field: 'body' }); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new EvidenceValidationError('Scanner delivery request body must be an object.', { field: 'body' });
  for (const key of Object.keys(value)) if (!allowed.has(key)) throw new EvidenceValidationError(`Scanner delivery request contains unsupported field ${key}.`, { field: key });
  return value;
}
function header(headers, name) { const value = headers?.[name] ?? headers?.[name.toLowerCase()]; const clean = Array.isArray(value) ? value[0] : String(value ?? '').trim(); if (!clean) throw new ExternalScanAuthenticationError(); return clean; }
function safeJobId(value) { const id = String(value ?? ''); if (!JOB_ID.test(id)) throw new EvidenceValidationError('jobId is invalid.', { field: 'jobId' }); return id; }
function safeEvidenceId(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId must be a valid EVD identifier.', { field: 'evidenceId' }); return id; }
function hashValue(value, field) { const clean = String(value ?? '').toLowerCase(); if (!HASH.test(clean)) throw new EvidenceValidationError(`${field} must be a lowercase SHA-256 digest.`, { field }); return clean; }
function safeReasonCode(value) { const clean = String(value ?? '').trim(); if (!/^[a-z0-9][a-z0-9._-]{1,63}$/.test(clean)) throw new EvidenceValidationError('reasonCode must be a safe machine-readable code.', { field: 'reasonCode' }); return clean; }
function identifier(value, field) { const clean = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@-]{1,191}$/.test(clean)) throw new EvidenceValidationError(`${field} must be a safe identifier.`, { field }); return clean; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new EvidenceValidationError(`${field} must be boolean.`, { field }); return value; }
function enumValue(value, allowed, field) { const clean = String(value ?? '').trim(); if (!allowed.has(clean)) throw new TypeError(`${field} is invalid.`); return clean; }
function validDate(value, field) { const date = new Date(value); if (Number.isNaN(date.getTime())) throw new ExternalScanAuthenticationError(`External scanner ${field} is invalid.`); return date; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
function disabledOutbox() {
  return Object.freeze({
    enabled: false,
    required: false,
    mode: 'disabled',
    queue() { throw new EvidenceConflictError('External scan job delivery is disabled.'); },
    claimSigned() { throw new EvidenceConflictError('External scan job delivery is disabled.'); },
    acknowledgeSigned() { throw new EvidenceConflictError('External scan job delivery is disabled.'); },
    failSigned() { throw new EvidenceConflictError('External scan job delivery is disabled.'); },
    completeFromAttestation() { return { matched: false, disabled: true }; },
    list() { return []; },
    latest() { return null; },
    tenantStatus() { return { status: 'disabled', enabled: false, required: false, mode: 'disabled', total: 0 }; },
    verify() { return { valid: true, disabled: true, checkedJobs: 0 }; },
    health() { return { status: 'disabled', enabled: false, required: false, mode: 'disabled' }; }
  });
}
