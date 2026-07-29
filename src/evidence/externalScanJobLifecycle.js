import { existsSync, mkdirSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import {
  atomicWriteEvidenceJson,
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson
} from './evidenceCrypto.js';
import {
  EvidenceIntegrityError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  ExternalScanJobStoreError,
  createExternalScanJobOutbox
} from './externalScanJobOutbox.js';

const RECORD_FORMAT = 'basitclaw-external-scan-job';
const ALL_STATES = ['pending', 'inflight', 'delivered', 'completed', 'dead-letter'];
const ACTIVE_EXPIRY_STATES = ['pending', 'delivered'];

export class ExternalScanClaimBudgetError extends EvidenceValidationError {
  constructor(details = {}) {
    super('The requested scanner claim could exceed the configured sealed-response byte budget.', details);
    this.name = 'ExternalScanClaimBudgetError';
    this.code = 'EXTERNAL_SCAN_CLAIM_BUDGET_EXCEEDED';
    this.statusCode = 413;
  }
}

export function createExternalScanJobLifecycle({
  outbox,
  janitor,
  maxClaimBytes = 25_000_000,
  maximumEvidenceBytes = 10_000_000
} = {}) {
  if (!outbox || typeof outbox.claimSigned !== 'function') throw new TypeError('An external scan job outbox is required.');
  if (!janitor || typeof janitor.run !== 'function') throw new TypeError('An external scan job janitor is required.');
  const byteBudget = integer(maxClaimBytes, 'maxClaimBytes', 1_000_000, 1_000_000_000);
  const evidenceLimit = integer(maximumEvidenceBytes, 'maximumEvidenceBytes', 1, 100_000_000);
  const estimatedPackageBytes = Math.ceil(evidenceLimit * 16 / 9) + 131_072;
  const maximumClaimJobs = Math.floor(byteBudget / estimatedPackageBytes);
  if (maximumClaimJobs < 1) {
    throw new TypeError('maxClaimBytes must accommodate at least one maximum-size sealed evidence package.');
  }

  function maintain() { return janitor.run(); }
  function queue(...args) { maintain(); return outbox.queue(...args); }
  function claimSigned(bodyBuffer, headers) {
    assertClaimBudget(bodyBuffer);
    maintain();
    return outbox.claimSigned(bodyBuffer, headers);
  }
  function acknowledgeSigned(...args) { maintain(); return outbox.acknowledgeSigned(...args); }
  function failSigned(...args) { maintain(); return outbox.failSigned(...args); }
  function completeFromAttestation(...args) { maintain(); return outbox.completeFromAttestation(...args); }
  function list(...args) { maintain(); return outbox.list(...args); }
  function latest(...args) { maintain(); return outbox.latest(...args); }
  function tenantStatus(...args) { maintain(); return outbox.tenantStatus(...args); }
  function verify(...args) { maintain(); return outbox.verify(...args); }
  function health() {
    try {
      const maintenance = maintain();
      return {
        ...outbox.health(),
        maxClaimBytes: byteBudget,
        estimatedMaximumPackageBytes: estimatedPackageBytes,
        maximumClaimJobs,
        expiryEnforced: true,
        maintenance
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, required: Boolean(outbox.required), mode: outbox.mode,
        maxClaimBytes: byteBudget, estimatedMaximumPackageBytes: estimatedPackageBytes,
        maximumClaimJobs, expiryEnforced: true, error: error?.code ?? 'external_scan_job_maintenance_failed'
      };
    }
  }

  function assertClaimBudget(bodyBuffer) {
    if (!Buffer.isBuffer(bodyBuffer)) throw new TypeError('Scanner claim body must be a Buffer.');
    let input;
    try { input = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
    catch { return; }
    if (!input || typeof input !== 'object' || Array.isArray(input)) return;
    const requested = input.limit === undefined ? 1 : Number(input.limit);
    if (Number.isInteger(requested) && requested > maximumClaimJobs) {
      throw new ExternalScanClaimBudgetError({
        requestedJobs: requested,
        maximumClaimJobs,
        maxClaimBytes: byteBudget,
        estimatedMaximumPackageBytes: estimatedPackageBytes
      });
    }
  }

  return Object.freeze({
    ...outbox,
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
    maintain,
    maxClaimBytes: byteBudget,
    maximumClaimJobs,
    estimatedMaximumPackageBytes: estimatedPackageBytes,
    expiryEnforced: true
  });
}

export function createExternalScanJobJanitor({
  directory,
  evidenceKeys,
  evidencePrimaryKeyId,
  deadLetterRetention = 2_000,
  now = () => new Date(),
  mutex = null
} = {}) {
  if (!String(directory ?? '').trim()) throw new TypeError('An external scan job directory is required.');
  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(evidenceKeys, evidencePrimaryKeyId);
  const deadLimit = integer(deadLetterRetention, 'deadLetterRetention', 1, 100_000);
  const stateDirectories = Object.fromEntries(ALL_STATES.map((state) => [state, resolve(root, state)]));
  for (const path of Object.values(stateDirectories)) mkdirSync(path, { recursive: true, mode: 0o700 });
  const lock = mutex ?? createFileMutex({ directory: resolve(root, '.locks'), now });

  function run() {
    return lock.withLock('external-scan-job-outbox', () => {
      const reconciled = reconcileLocationsLocked();
      let expiredPending = 0;
      let expiredDelivered = 0;
      for (const state of ACTIVE_EXPIRY_STATES) {
        const directoryPath = stateDirectories[state];
        for (const filename of jobNames(directoryPath)) {
          const source = resolve(directoryPath, filename);
          const jobId = filename.slice(0, -5);
          const record = readRecord(source, jobId);
          if (record.state !== state) {
            throw new EvidenceIntegrityError('An external scan job is stored in the wrong expiry state directory.', { jobId, state });
          }
          if (new Date(record.expiresAt).getTime() > now().getTime()) continue;
          const reasonCode = state === 'pending' ? 'job_expired' : 'attestation_timeout';
          moveToDeadLetter(source, record, reasonCode);
          if (state === 'pending') expiredPending += 1;
          else expiredDelivered += 1;
        }
      }
      pruneDeadLetters();
      return { reconciled, expiredPending, expiredDelivered };
    });
  }

  function reconcileLocationsLocked() {
    let reconciled = 0;
    for (const directoryState of ALL_STATES) {
      for (const filename of jobNames(stateDirectories[directoryState])) {
        const source = resolve(stateDirectories[directoryState], filename);
        const jobId = filename.slice(0, -5);
        const record = readRecord(source, jobId);
        if (record.state === directoryState) continue;
        if (!ALL_STATES.includes(record.state)) throw new EvidenceIntegrityError('An external scan job has an unsupported state.', { jobId, state: record.state });
        const target = resolve(stateDirectories[record.state], filename);
        if (existsSync(target)) throw new EvidenceIntegrityError('An external scan job exists in multiple state directories.', { jobId });
        renameSync(source, target);
        reconciled += 1;
      }
    }
    return reconciled;
  }

  function moveToDeadLetter(source, record, reasonCode) {
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
      result: { delivery: 'dead-letter', reasonCode }
    };
    const target = resolve(stateDirectories['dead-letter'], `${record.jobId}.json`);
    if (existsSync(target)) throw new EvidenceIntegrityError('The expired external scan job already exists in dead-letter storage.', { jobId: record.jobId });
    atomicWriteEvidenceJson(source, encryptEvidenceJson(next, keyring, recordAad(record.jobId)));
    renameSync(source, target);
  }

  function readRecord(path, jobId) {
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new ExternalScanJobStoreError('An external scan job record is unreadable during expiry maintenance.', { jobId }, error); }
    const record = decryptEvidenceJson(envelope, keyring, recordAad(jobId), EvidenceIntegrityError);
    if (!record || record.format !== RECORD_FORMAT || record.version !== 1 || record.jobId !== jobId || !record.management) {
      throw new EvidenceIntegrityError('An external scan job record is invalid during expiry maintenance.', { jobId });
    }
    return record;
  }

  function pruneDeadLetters() {
    const names = jobNames(stateDirectories['dead-letter']);
    for (const filename of names.slice(0, Math.max(0, names.length - deadLimit))) {
      rmSync(resolve(stateDirectories['dead-letter'], filename), { force: true });
    }
  }

  return Object.freeze({ run, directory: root, deadLetterRetention: deadLimit });
}

export function createManagedExternalScanJobOutboxFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  const mode = environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_MODE) ?? 'disabled';
  const required = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_REQUIRED) ?? false);
  if (mode === 'disabled') return createExternalScanJobOutbox({ mode, required });
  if (!evidenceRegistry?.enabled || !evidenceRegistry.directory) throw new ExternalScanJobStoreError('Scanner delivery requires enabled evidence custody.');

  let evidenceKeys;
  let providers;
  try {
    evidenceKeys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS));
    providers = normaliseProviderDeliveryKeys(JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS)));
  } catch (error) {
    throw new ExternalScanJobStoreError('Scanner delivery configuration JSON or primary RSA key selection is invalid.', {}, error);
  }
  const directory = environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_DIR)
    ?? resolve(evidenceRegistry.directory, '.external-scan-jobs');
  const deadLetterRetention = environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_DEAD_LETTER_RETENTION) ?? 2_000;
  try {
    const outbox = createExternalScanJobOutbox({
      mode,
      required,
      directory,
      evidenceKeys,
      evidencePrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      providers,
      jobTtlMinutes: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_JOB_TTL_MINUTES) ?? 1440,
      claimLeaseMs: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_CLAIM_LEASE_MS) ?? 300_000,
      maxAttempts: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_MAX_DELIVERY_ATTEMPTS) ?? 5,
      completedRetention: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_COMPLETED_RETENTION) ?? 10_000,
      deadLetterRetention,
      clockSkewSeconds: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCANNER_CLOCK_SKEW_SECONDS) ?? 300
    });
    const janitor = createExternalScanJobJanitor({
      directory,
      evidenceKeys,
      evidencePrimaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID),
      deadLetterRetention
    });
    return createExternalScanJobLifecycle({
      outbox,
      janitor,
      maxClaimBytes: environmentValue(env.WORKFORCE_AUDIT_EXTERNAL_SCAN_MAX_CLAIM_BYTES) ?? 25_000_000,
      maximumEvidenceBytes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_MAX_BYTES) ?? 10_000_000
    });
  } catch (error) {
    if (error instanceof ExternalScanJobStoreError) throw error;
    throw new ExternalScanJobStoreError('Managed scanner delivery configuration is invalid.', { reason: error?.code ?? 'invalid_configuration' }, error);
  }
}

export function normaliseProviderDeliveryKeys(providers) {
  if (!providers || typeof providers !== 'object' || Array.isArray(providers)) throw new TypeError('External scanner providers must be an object.');
  return Object.fromEntries(Object.entries(providers).map(([providerId, provider]) => {
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`External scanner provider ${providerId} must be an object.`);
    const publicKeys = provider.publicKeys ?? {};
    const primary = provider.primaryPublicKeyId;
    if (primary === undefined || primary === null || primary === '') return [providerId, { ...provider }];
    if (!Object.prototype.hasOwnProperty.call(publicKeys, primary)) {
      throw new TypeError(`External scanner provider ${providerId} primaryPublicKeyId is not present in publicKeys.`);
    }
    const ordered = Object.fromEntries([
      ...Object.entries(publicKeys).filter(([keyId]) => keyId !== primary),
      [primary, publicKeys[primary]]
    ]);
    return [providerId, { ...provider, publicKeys: ordered }];
  }));
}

function recordAad(jobId) { return `basitclaw:external-scan-job-record:${jobId}`; }
function jobNames(directory) { return readdirSync(directory).filter((name) => /^SCNJOB-[a-f0-9]{32}\.json$/.test(name)).sort(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return parsed; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
