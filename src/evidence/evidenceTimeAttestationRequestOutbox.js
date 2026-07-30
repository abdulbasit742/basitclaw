import {
  constants,
  createPublicKey,
  randomUUID,
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
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const INDEX_FORMAT = 'basitclaw-evidence-notary-request-index';
const JOB_FORMAT = 'basitclaw-evidence-notary-request-job';
const EVENT_FORMAT = 'basitclaw-evidence-notary-request-event';
const AUTH_FORMAT = 'basitclaw-evidence-notary-request-auth-v1';
const MODES = new Set(['disabled', 'pull']);
const STATES = new Set(['pending', 'inflight', 'delivered', 'completed', 'dead-letter']);
const ALGORITHMS = new Set(['ed25519', 'rsa-pss-sha256']);
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;
const JOB_ID = /^NTR-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const NONCE = /^[a-zA-Z0-9][a-zA-Z0-9._:-]{15,127}$/;
const REASON = /^[a-z][a-z0-9._-]{2,63}$/;
const CLAIM_FIELDS = new Set(['action', 'providerId', 'keyId', 'timestamp', 'nonce', 'limit', 'signature']);
const ACK_FIELDS = new Set(['action', 'providerId', 'keyId', 'timestamp', 'nonce', 'jobId', 'claimToken', 'signature']);
const FAIL_FIELDS = new Set(['action', 'providerId', 'keyId', 'timestamp', 'nonce', 'jobId', 'claimToken', 'retryable', 'reasonCode', 'signature']);

export class EvidenceNotaryRequestStoreError extends EvidenceStoreError {
  constructor(message = 'The evidence-notary request outbox is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceNotaryRequestStoreError';
    this.code = 'EVIDENCE_NOTARY_REQUEST_STORE_UNAVAILABLE';
  }
}

export class EvidenceNotaryRequestAuthenticationError extends Error {
  constructor(message = 'The time-authority request signature is invalid.', details = {}) {
    super(message);
    this.name = 'EvidenceNotaryRequestAuthenticationError';
    this.code = 'EVIDENCE_NOTARY_REQUEST_AUTHENTICATION_FAILED';
    this.statusCode = 401;
    this.details = details;
  }
}

export function createEvidenceTimeAttestationRequestOutbox({
  mode = 'disabled',
  required = false,
  directory,
  encryptionKeys,
  encryptionPrimaryKeyId,
  providers,
  jobTtlMinutes = 1440,
  claimLeaseMs = 300_000,
  maxAttempts = 5,
  completedRetention = 10_000,
  deadLetterRetention = 2_000,
  eventRetention = 50_000,
  clockSkewSeconds = 300,
  now = () => new Date(),
  mutexFactory = null
} = {}) {
  const selectedMode = enumValue(mode, MODES, 'mode');
  const isRequired = booleanValue(required, 'required');
  if (selectedMode === 'disabled') {
    if (isRequired) throw new TypeError('Required evidence-notary request delivery cannot be disabled.');
    return disabledOutbox();
  }
  if (!String(directory ?? '').trim()) throw new TypeError('An evidence-notary request directory is required.');

  const root = resolve(String(directory));
  const keyring = parseEvidenceKeyring(encryptionKeys, encryptionPrimaryKeyId);
  const authorityProviders = parseProviders(providers);
  const ttlMs = integer(jobTtlMinutes, 'jobTtlMinutes', 1, 43_200) * 60_000;
  const leaseMs = integer(claimLeaseMs, 'claimLeaseMs', 1_000, 3_600_000);
  const attemptsLimit = integer(maxAttempts, 'maxAttempts', 1, 100);
  const completedLimit = integer(completedRetention, 'completedRetention', 100, 1_000_000);
  const deadLimit = integer(deadLetterRetention, 'deadLetterRetention', 1, 100_000);
  const eventsLimit = integer(eventRetention, 'eventRetention', 100, 1_000_000);
  const skewMs = integer(clockSkewSeconds, 'clockSkewSeconds', 1, 3600) * 1000;
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const mutexes = new Map();

  function queue(challengeInput, providerId, { actor, purpose } = {}) {
    const challenge = normaliseChallenge(challengeInput);
    const provider = providerIdentifier(providerId);
    requireProvider(provider);
    const queuedBy = identifier(actor, 'actor');
    const requestPurpose = cleanText(purpose, 'purpose', 10, 500);
    const jobId = jobIdFor(challenge, provider);
    return withProviderLock(provider, () => {
      const index = loadIndex(provider);
      maintainIndex(index);
      const existing = index.jobs.find((job) => job.jobId === jobId);
      if (existing) return { queued: false, duplicate: true, job: publicJob(existing) };
      const createdAt = nowIso();
      const job = hashJob({
        format: JOB_FORMAT,
        version: 1,
        jobId,
        providerId: provider,
        tenantId: challenge.tenantId,
        archiveId: challenge.archiveId,
        receiptSha256: challenge.receiptSha256,
        objectEnvelopeSha256: challenge.objectEnvelopeSha256,
        archivedAt: challenge.archivedAt,
        retentionUntil: challenge.retentionUntil,
        state: 'pending',
        createdAt,
        updatedAt: createdAt,
        expiresAt: new Date(now().getTime() + ttlMs).toISOString(),
        attempts: 0,
        nextAttemptAt: createdAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        deliveredAt: null,
        completedAt: null,
        deadLetteredAt: null,
        queuedBy,
        purpose: requestPurpose,
        result: null
      });
      index.jobs.push(job);
      appendEvent(index, job, 'queued', { actor: queuedBy });
      saveIndex(provider, index);
      return { queued: true, duplicate: false, job: publicJob(job) };
    });
  }

  function requeue(tenantId, jobId, { actor, purpose } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const id = safeJobId(jobId);
    const requeuedBy = identifier(actor, 'actor');
    const requestPurpose = cleanText(purpose, 'purpose', 10, 500);
    const provider = providerForJobId(id);
    return withProviderLock(provider, () => {
      const index = loadIndex(provider);
      maintainIndex(index);
      const position = index.jobs.findIndex((job) => job.jobId === id);
      if (position < 0) throw new EvidenceConflictError('The evidence-notary request was not found.', { jobId: id });
      const current = index.jobs[position];
      assertTenant(current, tenant);
      if (current.state !== 'dead-letter') {
        throw new EvidenceConflictError('Only a dead-letter evidence-notary request can be requeued.', { jobId: id, state: current.state });
      }
      const updatedAt = nowIso();
      const next = hashJob({
        ...withoutHash(current),
        state: 'pending',
        updatedAt,
        expiresAt: new Date(now().getTime() + ttlMs).toISOString(),
        attempts: 0,
        nextAttemptAt: updatedAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        deliveredAt: null,
        completedAt: null,
        deadLetteredAt: null,
        queuedBy: requeuedBy,
        purpose: requestPurpose,
        result: { action: 'requeued' }
      });
      index.jobs[position] = next;
      appendEvent(index, next, 'requeued', { actor: requeuedBy });
      saveIndex(provider, index);
      return { requeued: true, job: publicJob(next) };
    });
  }

  function claimSigned(input) {
    const authenticated = authenticateAction(input, 'claim', CLAIM_FIELDS);
    const limit = integer(authenticated.input.limit ?? 1, 'limit', 1, 100);
    return withProviderLock(authenticated.providerId, () => {
      const index = loadIndex(authenticated.providerId);
      maintainIndex(index);
      consumeReplay(index, authenticated);
      const jobs = [];
      for (let position = 0; position < index.jobs.length && jobs.length < limit; position += 1) {
        const current = index.jobs[position];
        if (current.providerId !== authenticated.providerId || current.state !== 'pending') continue;
        if (new Date(current.nextAttemptAt).getTime() > now().getTime()) continue;
        const claimToken = randomUUID();
        const claimedAt = nowIso();
        const next = hashJob({
          ...withoutHash(current),
          state: 'inflight',
          updatedAt: claimedAt,
          attempts: current.attempts + 1,
          claimToken,
          claimedAt,
          claimExpiresAt: new Date(now().getTime() + leaseMs).toISOString(),
          result: { action: 'claimed', keyId: authenticated.keyId }
        });
        index.jobs[position] = next;
        appendEvent(index, next, 'claimed', { keyId: authenticated.keyId });
        jobs.push({
          jobId: next.jobId,
          claimToken,
          claimExpiresAt: next.claimExpiresAt,
          challenge: publicChallenge(next)
        });
      }
      saveIndex(authenticated.providerId, index);
      return { providerId: authenticated.providerId, jobs };
    });
  }

  function acknowledgeSigned(jobId, input) {
    const id = safeJobId(jobId);
    const authenticated = authenticateAction(input, 'acknowledge', ACK_FIELDS, id);
    return withProviderLock(authenticated.providerId, () => {
      const index = loadIndex(authenticated.providerId);
      maintainIndex(index);
      consumeReplay(index, authenticated);
      const position = findJob(index, id);
      const current = index.jobs[position];
      assertOwnedClaim(current, authenticated.providerId, authenticated.input.claimToken);
      const deliveredAt = nowIso();
      const next = hashJob({
        ...withoutHash(current),
        state: 'delivered',
        updatedAt: deliveredAt,
        deliveredAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        result: { action: 'acknowledged', keyId: authenticated.keyId }
      });
      index.jobs[position] = next;
      appendEvent(index, next, 'acknowledged', { keyId: authenticated.keyId });
      saveIndex(authenticated.providerId, index);
      return publicJob(next);
    });
  }

  function failSigned(jobId, input) {
    const id = safeJobId(jobId);
    const authenticated = authenticateAction(input, 'fail', FAIL_FIELDS, id);
    const retryable = booleanValue(authenticated.input.retryable, 'retryable');
    const reasonCode = reasonIdentifier(authenticated.input.reasonCode);
    return withProviderLock(authenticated.providerId, () => {
      const index = loadIndex(authenticated.providerId);
      maintainIndex(index);
      consumeReplay(index, authenticated);
      const position = findJob(index, id);
      const current = index.jobs[position];
      assertOwnedClaim(current, authenticated.providerId, authenticated.input.claimToken);
      let next;
      if (retryable && current.attempts < attemptsLimit && new Date(current.expiresAt).getTime() > now().getTime()) {
        const updatedAt = nowIso();
        next = hashJob({
          ...withoutHash(current),
          state: 'pending',
          updatedAt,
          nextAttemptAt: updatedAt,
          claimToken: null,
          claimedAt: null,
          claimExpiresAt: null,
          result: { action: 'retry', reasonCode, keyId: authenticated.keyId }
        });
        appendEvent(index, next, 'retry_scheduled', { reasonCode, keyId: authenticated.keyId });
      } else {
        next = deadLetter(index, current, retryable ? 'attempts_exhausted' : reasonCode);
      }
      index.jobs[position] = next;
      pruneTerminal(index);
      saveIndex(authenticated.providerId, index);
      return publicJob(next);
    });
  }

  function completeFromAttestation(input, attestation = null) {
    if (!input || typeof input !== 'object') return { matched: false };
    const challenge = normaliseChallenge({
      tenantId: input.tenantId,
      archiveId: input.archiveId,
      receiptSha256: input.receiptSha256,
      objectEnvelopeSha256: input.objectEnvelopeSha256,
      archivedAt: input.timestamp,
      retentionUntil: input.timestamp
    }, { allowSyntheticDates: true });
    const provider = providerIdentifier(input.providerId);
    if (!authorityProviders.has(provider)) return { matched: false };
    const jobId = jobIdFor(challenge, provider);
    return withProviderLock(provider, () => {
      const index = loadIndex(provider);
      maintainIndex(index);
      const position = index.jobs.findIndex((job) => job.jobId === jobId);
      if (position < 0) return { matched: false, jobId };
      const current = index.jobs[position];
      assertAttestationMatch(current, input);
      if (current.state === 'completed') return { matched: true, duplicate: true, job: publicJob(current) };
      const completedAt = nowIso();
      const next = hashJob({
        ...withoutHash(current),
        state: 'completed',
        updatedAt: completedAt,
        completedAt,
        claimToken: null,
        claimedAt: null,
        claimExpiresAt: null,
        result: {
          action: 'attested',
          attestationId: attestation?.attestationId ?? null,
          policyId: attestation?.policyId ?? input.policyId ?? null,
          authorityTimestamp: attestation?.timestamp ?? input.timestamp ?? null
        }
      });
      index.jobs[position] = next;
      appendEvent(index, next, 'completed', { attestationId: next.result.attestationId });
      pruneTerminal(index);
      saveIndex(provider, index);
      return { matched: true, duplicate: false, job: publicJob(next) };
    });
  }

  function list(tenantId, { archiveId = null, providerId = null, limit = 500 } = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const archive = archiveId === null ? null : archiveIdentifier(archiveId);
    const selectedProviders = providerId === null
      ? [...authorityProviders.keys()]
      : [providerIdentifier(providerId)];
    const rows = [];
    for (const provider of selectedProviders) {
      requireProvider(provider);
      withProviderLock(provider, () => {
        const index = loadIndex(provider);
        maintainIndex(index);
        for (const job of index.jobs) {
          if (job.tenantId !== tenant || (archive && job.archiveId !== archive)) continue;
          rows.push(publicJob(job));
        }
        saveIndex(provider, index);
      });
    }
    return rows
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
      .slice(0, integer(limit, 'limit', 1, 5000));
  }

  function verifyTenant(tenantId) {
    const tenant = identifier(tenantId, 'tenantId');
    let checkedJobs = 0;
    let checkedEvents = 0;
    for (const provider of authorityProviders.keys()) {
      withProviderLock(provider, () => {
        const index = loadIndex(provider);
        for (const job of index.jobs) if (job.tenantId === tenant) checkedJobs += 1;
        checkedEvents += index.events.filter((event) => {
          const job = index.jobs.find((entry) => entry.jobId === event.jobId);
          return job?.tenantId === tenant;
        }).length;
      });
    }
    return { valid: true, tenantId: tenant, checkedJobs, checkedEvents };
  }

  function tenantStatus(tenantId) {
    try {
      const jobs = list(tenantId, { limit: 5000 });
      const counts = stateCounts(jobs);
      return {
        status: counts['dead-letter'] ? 'attention' : 'ready',
        enabled: true,
        required: isRequired,
        mode: selectedMode,
        total: jobs.length,
        ...counts
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, required: isRequired, mode: selectedMode,
        error: error?.code ?? 'evidence_notary_request_store_unavailable'
      };
    }
  }

  function health() {
    try {
      let totalJobs = 0;
      let deadLetters = 0;
      let replayEntries = 0;
      for (const provider of authorityProviders.keys()) {
        withProviderLock(provider, () => {
          const index = loadIndex(provider);
          maintainIndex(index);
          totalJobs += index.jobs.length;
          deadLetters += index.jobs.filter((job) => job.state === 'dead-letter').length;
          replayEntries += index.replays.length;
          saveIndex(provider, index);
        });
      }
      return {
        status: deadLetters ? 'degraded' : 'ready',
        enabled: true,
        required: isRequired,
        mode: selectedMode,
        durable: true,
        encryptedRecords: true,
        plaintextEvidenceQueued: false,
        evidenceBytesQueued: false,
        arbitraryOutboundUrls: false,
        asymmetricRequestAuthentication: true,
        requestReplayProtected: true,
        providerPartitioned: true,
        transitionHashChain: true,
        providerCount: authorityProviders.size,
        jobTtlMinutes: ttlMs / 60_000,
        claimLeaseMs: leaseMs,
        maxAttempts: attemptsLimit,
        totalJobs,
        deadLetters,
        replayEntries
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, required: isRequired, mode: selectedMode,
        error: error?.code ?? 'evidence_notary_request_store_unavailable'
      };
    }
  }

  function authenticateAction(input, expectedAction, allowedFields, expectedJobId = null) {
    const request = strictObject(input, allowedFields, 'evidence-notary authority request');
    if (request.action !== expectedAction) {
      throw new EvidenceNotaryRequestAuthenticationError('The authority request action is invalid.', { reason: 'action_mismatch' });
    }
    const providerId = providerIdentifier(request.providerId);
    const keyId = identifier(request.keyId, 'keyId');
    const provider = authorityProviders.get(providerId);
    const authority = provider?.get(keyId);
    if (!authority) {
      throw new EvidenceNotaryRequestAuthenticationError(undefined, { reason: 'unknown_authority_key', providerId, keyId });
    }
    const timestamp = isoDate(request.timestamp, 'timestamp');
    const nonce = String(request.nonce ?? '');
    if (!NONCE.test(nonce)) throw new EvidenceNotaryRequestAuthenticationError('The authority request nonce is invalid.', { reason: 'nonce_invalid' });
    if (Math.abs(now().getTime() - new Date(timestamp).getTime()) > skewMs) {
      throw new EvidenceNotaryRequestAuthenticationError('The authority request timestamp is outside the allowed clock-skew window.', { reason: 'timestamp_out_of_window' });
    }
    if (expectedJobId && safeJobId(request.jobId) !== expectedJobId) {
      throw new EvidenceNotaryRequestAuthenticationError('The authority request job does not match the route.', { reason: 'job_mismatch' });
    }
    const canonical = canonicalEvidenceNotaryRequest({ ...request, timestamp });
    verifyAuthoritySignature(authority, canonical, request.signature, providerId, keyId);
    return {
      input: { ...request, timestamp },
      providerId,
      keyId,
      replayId: sha256(`${canonical}\n${request.signature}`)
    };
  }

  function consumeReplay(index, authentication) {
    const current = now().getTime();
    index.replays = index.replays.filter((entry) => new Date(entry.expiresAt).getTime() > current);
    if (index.replays.some((entry) => entry.replayId === authentication.replayId)) {
      throw new EvidenceNotaryRequestAuthenticationError('The authority request replay was rejected.', { reason: 'replay_detected' });
    }
    index.replays.push({
      replayId: authentication.replayId,
      acceptedAt: nowIso(),
      expiresAt: new Date(current + skewMs * 2).toISOString()
    });
  }

  function maintainIndex(index) {
    const current = now().getTime();
    for (let position = 0; position < index.jobs.length; position += 1) {
      const job = index.jobs[position];
      if (job.state === 'inflight' && new Date(job.claimExpiresAt ?? 0).getTime() <= current) {
        if (job.attempts < attemptsLimit && new Date(job.expiresAt).getTime() > current) {
          const updatedAt = nowIso();
          const next = hashJob({
            ...withoutHash(job),
            state: 'pending',
            updatedAt,
            nextAttemptAt: updatedAt,
            claimToken: null,
            claimedAt: null,
            claimExpiresAt: null,
            result: { action: 'claim_recovered' }
          });
          index.jobs[position] = next;
          appendEvent(index, next, 'claim_recovered', {});
        } else {
          index.jobs[position] = deadLetter(index, job, 'claim_expired');
        }
        continue;
      }
      if (['pending', 'delivered'].includes(job.state) && new Date(job.expiresAt).getTime() <= current) {
        index.jobs[position] = deadLetter(index, job, job.state === 'delivered' ? 'attestation_timeout' : 'job_expired');
      }
    }
    index.replays = index.replays.filter((entry) => new Date(entry.expiresAt).getTime() > current);
    pruneTerminal(index);
  }

  function deadLetter(index, current, reasonCode) {
    const deadLetteredAt = nowIso();
    const next = hashJob({
      ...withoutHash(current),
      state: 'dead-letter',
      updatedAt: deadLetteredAt,
      deadLetteredAt,
      claimToken: null,
      claimedAt: null,
      claimExpiresAt: null,
      result: { action: 'dead-letter', reasonCode: reasonIdentifier(reasonCode) }
    });
    appendEvent(index, next, 'dead_lettered', { reasonCode: next.result.reasonCode });
    return next;
  }

  function pruneTerminal(index) {
    pruneState(index, 'completed', completedLimit, 'completedAt');
    pruneState(index, 'dead-letter', deadLimit, 'deadLetteredAt');
    while (index.events.length > eventsLimit) {
      const removed = index.events.shift();
      index.anchorSequence = removed.sequence;
      index.anchorHash = removed.hash;
    }
  }

  function pruneState(index, state, limit, timestampField) {
    const terminal = index.jobs
      .filter((job) => job.state === state)
      .sort((left, right) => String(left[timestampField] ?? '').localeCompare(String(right[timestampField] ?? '')));
    const remove = new Set(terminal.slice(0, Math.max(0, terminal.length - limit)).map((job) => job.jobId));
    if (remove.size) index.jobs = index.jobs.filter((job) => !remove.has(job.jobId));
  }

  function appendEvent(index, job, type, details) {
    const event = {
      format: EVENT_FORMAT,
      version: 1,
      sequence: index.sequence + 1,
      previousHash: index.headHash,
      jobId: job.jobId,
      type,
      state: job.state,
      timestamp: nowIso(),
      details: details ?? {}
    };
    event.hash = eventHash(event);
    index.events.push(event);
    index.sequence = event.sequence;
    index.headHash = event.hash;
    index.updatedAt = event.timestamp;
  }

  function loadIndex(providerId) {
    const path = indexPath(providerId);
    if (!existsSync(path)) return emptyIndex(providerId);
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) { throw new EvidenceNotaryRequestStoreError('A notary-request provider index is unreadable.', { providerId }, error); }
    const index = decryptEvidenceJson(envelope, keyring, indexAad(providerId), EvidenceIntegrityError);
    validateIndex(index, providerId);
    return index;
  }

  function saveIndex(providerId, index) {
    validateIndex(index, providerId);
    atomicWriteEvidenceJson(indexPath(providerId), encryptEvidenceJson(index, keyring, indexAad(providerId)));
  }

  function validateIndex(index, providerId) {
    if (!index || index.format !== INDEX_FORMAT || index.version !== 1 || index.providerId !== providerId
        || !Array.isArray(index.jobs) || !Array.isArray(index.events) || !Array.isArray(index.replays)) {
      throw new EvidenceIntegrityError('An evidence-notary request index has an invalid identity.', { providerId });
    }
    const ids = new Set();
    for (const job of index.jobs) {
      validateJob(job, providerId);
      if (ids.has(job.jobId)) throw new EvidenceIntegrityError('Duplicate notary-request job identity detected.', { jobId: job.jobId });
      ids.add(job.jobId);
    }
    verifyEventChain(index);
    for (const replay of index.replays) {
      if (!HASH.test(String(replay.replayId ?? '')) || Number.isNaN(new Date(replay.expiresAt).getTime())) {
        throw new EvidenceIntegrityError('An evidence-notary replay record is invalid.', { providerId });
      }
    }
  }

  function verifyEventChain(index) {
    let previousHash = index.anchorHash ?? null;
    let expectedSequence = Number(index.anchorSequence ?? 0) + 1;
    for (const event of index.events) {
      if (event.sequence !== expectedSequence || event.previousHash !== previousHash || event.hash !== eventHash(event)) {
        throw new EvidenceIntegrityError('The evidence-notary request transition chain is invalid.', { providerId: index.providerId, expectedSequence });
      }
      previousHash = event.hash;
      expectedSequence += 1;
    }
    const expectedHead = index.events.length ? previousHash : (index.anchorHash ?? null);
    const expectedHeadSequence = index.events.length ? expectedSequence - 1 : Number(index.anchorSequence ?? 0);
    if (index.sequence !== expectedHeadSequence || index.headHash !== expectedHead) {
      throw new EvidenceIntegrityError('The evidence-notary request transition head is inconsistent.', { providerId: index.providerId });
    }
  }

  function validateJob(job, providerId) {
    if (!job || job.format !== JOB_FORMAT || job.version !== 1 || job.providerId !== providerId
        || !JOB_ID.test(String(job.jobId ?? '')) || !STATES.has(job.state)
        || !ARCHIVE_ID.test(String(job.archiveId ?? '')) || !HASH.test(String(job.receiptSha256 ?? ''))
        || !HASH.test(String(job.objectEnvelopeSha256 ?? '')) || job.hash !== jobHash(job)) {
      throw new EvidenceIntegrityError('An evidence-notary request job is invalid.', { providerId, jobId: job?.jobId });
    }
  }

  function withProviderLock(providerId, callback) {
    const provider = providerIdentifier(providerId);
    const mutex = mutexFor(provider);
    return mutex.withLock(`evidence-notary-requests:${provider}`, callback);
  }

  function mutexFor(providerId) {
    if (!mutexes.has(providerId)) {
      const directory = resolve(root, sha256(providerId), '.locks');
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      mutexes.set(providerId, mutexFactory?.(directory, providerId) ?? createFileMutex({ directory, now }));
    }
    return mutexes.get(providerId);
  }

  function indexPath(providerId) {
    const directory = resolve(root, sha256(providerId));
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    return resolve(directory, 'notary-requests.evidence');
  }

  function providerForJobId(jobId) {
    for (const provider of authorityProviders.keys()) {
      const index = loadIndex(provider);
      if (index.jobs.some((job) => job.jobId === jobId)) return provider;
    }
    throw new EvidenceConflictError('The evidence-notary request was not found.', { jobId });
  }

  function findJob(index, jobId) {
    const position = index.jobs.findIndex((job) => job.jobId === jobId);
    if (position < 0) throw new EvidenceConflictError('The evidence-notary request was not found.', { jobId });
    return position;
  }

  function assertOwnedClaim(job, providerId, claimToken) {
    const token = identifier(claimToken, 'claimToken');
    if (job.state !== 'inflight' || job.providerId !== providerId || job.claimToken !== token
        || new Date(job.claimExpiresAt ?? 0).getTime() <= now().getTime()) {
      throw new EvidenceConflictError('The evidence-notary request claim is no longer owned.', { jobId: job.jobId });
    }
  }

  function assertTenant(job, tenantId) {
    if (job.tenantId !== tenantId) throw new EvidenceConflictError('The evidence-notary request was not found.', { jobId: job.jobId });
  }

  function assertAttestationMatch(job, input) {
    if (job.tenantId !== input.tenantId || job.archiveId !== input.archiveId
        || job.providerId !== input.providerId || job.receiptSha256 !== input.receiptSha256
        || job.objectEnvelopeSha256 !== input.objectEnvelopeSha256) {
      throw new EvidenceIntegrityError('A time attestation does not match its queued notary request.', { jobId: job.jobId });
    }
  }

  function requireProvider(providerId) {
    if (!authorityProviders.has(providerId)) throw new EvidenceConflictError('The selected time authority is not configured.', { providerId });
  }

  function nowIso() { return now().toISOString(); }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    required: isRequired,
    directory: root,
    providerIds: Object.freeze([...authorityProviders.keys()].sort()),
    queue,
    requeue,
    claimSigned,
    acknowledgeSigned,
    failSigned,
    completeFromAttestation,
    list,
    verifyTenant,
    tenantStatus,
    health
  });
}

export function createEvidenceTimeAttestationRequestOutboxFromEnvironment({ env = process.env } = {}) {
  try {
    const mode = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_MODE) ?? 'disabled';
    const required = parseBoolean(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_REQUIRED) ?? false);
    if (mode === 'disabled') return createEvidenceTimeAttestationRequestOutbox({ mode, required });
    const rawKeys = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_KEYS);
    const primaryKeyId = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_PRIMARY_KEY_ID);
    const rawProviders = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS);
    if (!rawKeys || !primaryKeyId || !rawProviders) {
      throw new EvidenceNotaryRequestStoreError('Notary-request keys, primary key ID and authority providers are required.', {
        reason: 'missing_notary_request_configuration'
      });
    }
    return createEvidenceTimeAttestationRequestOutbox({
      mode,
      required,
      directory: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_DIR)
        ?? '.runtime-data/workforce-audit-evidence-notary-requests',
      encryptionKeys: JSON.parse(rawKeys),
      encryptionPrimaryKeyId: primaryKeyId,
      providers: JSON.parse(rawProviders),
      jobTtlMinutes: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_TTL_MINUTES) ?? 1440,
      claimLeaseMs: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_CLAIM_LEASE_MS) ?? 300_000,
      maxAttempts: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_MAX_ATTEMPTS) ?? 5,
      completedRetention: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_COMPLETED_RETENTION) ?? 10_000,
      deadLetterRetention: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_DEAD_LETTER_RETENTION) ?? 2_000,
      eventRetention: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_EVENT_RETENTION) ?? 50_000,
      clockSkewSeconds: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_CLOCK_SKEW_SECONDS) ?? 300
    });
  } catch (error) {
    if (error instanceof EvidenceNotaryRequestStoreError) throw error;
    throw new EvidenceNotaryRequestStoreError('Evidence-notary request configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

export function canonicalEvidenceNotaryRequest(input) {
  const body = { ...input };
  delete body.signature;
  const timestamp = isoDate(body.timestamp, 'timestamp');
  return [
    AUTH_FORMAT,
    body.action,
    body.providerId,
    body.keyId,
    timestamp,
    body.nonce,
    sha256(stableStringify({ ...body, timestamp }))
  ].join('\n');
}

function parseProviders(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Time-authority providers must be an object.');
  const providers = new Map();
  for (const [providerId, provider] of Object.entries(raw)) {
    providerIdentifier(providerId);
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`Provider ${providerId} must be an object.`);
    const rawKeys = provider.keys;
    if (!rawKeys || typeof rawKeys !== 'object' || Array.isArray(rawKeys) || !Object.keys(rawKeys).length) {
      throw new TypeError(`Provider ${providerId} must contain signing keys.`);
    }
    const keys = new Map();
    for (const [keyId, config] of Object.entries(rawKeys)) {
      identifier(keyId, 'keyId');
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Provider key ${providerId}/${keyId} must be an object.`);
      const algorithm = enumValue(config.algorithm, ALGORITHMS, 'algorithm');
      const publicKey = createPublicKey(String(config.publicKeyPem ?? ''));
      if (algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Provider key ${providerId}/${keyId} must be Ed25519.`);
      if (algorithm === 'rsa-pss-sha256') {
        if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) throw new TypeError(`Provider key ${providerId}/${keyId} must be RSA.`);
        if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Provider key ${providerId}/${keyId} must be at least 2048 bits.`);
      }
      keys.set(keyId, Object.freeze({ algorithm, publicKey }));
    }
    providers.set(providerId, keys);
  }
  if (!providers.size || providers.size > 20) throw new TypeError('Time-authority providers must contain 1 to 20 providers.');
  return providers;
}

function verifyAuthoritySignature(authority, canonical, encodedSignature, providerId, keyId) {
  let signature;
  try { signature = strictBase64(encodedSignature, 'authority request signature'); }
  catch {
    throw new EvidenceNotaryRequestAuthenticationError('The authority request signature is malformed.', {
      reason: 'signature_encoding', providerId, keyId
    });
  }
  const data = Buffer.from(canonical, 'utf8');
  let valid = false;
  try {
    valid = authority.algorithm === 'ed25519'
      ? verifyAsymmetric(null, data, authority.publicKey, signature)
      : verifyAsymmetric('sha256', data, {
        key: authority.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO
      }, signature);
  } catch {
    valid = false;
  }
  if (!valid) throw new EvidenceNotaryRequestAuthenticationError(undefined, { reason: 'signature_invalid', providerId, keyId });
}

function emptyIndex(providerId) {
  const timestamp = new Date().toISOString();
  return {
    format: INDEX_FORMAT,
    version: 1,
    providerId,
    createdAt: timestamp,
    updatedAt: timestamp,
    sequence: 0,
    headHash: null,
    anchorSequence: 0,
    anchorHash: null,
    jobs: [],
    events: [],
    replays: []
  };
}

function normaliseChallenge(input, { allowSyntheticDates = false } = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid notary challenge is required.');
  const archivedAt = isoDate(input.archivedAt, 'archivedAt');
  const retentionUntil = isoDate(input.retentionUntil, 'retentionUntil');
  if (!allowSyntheticDates && new Date(retentionUntil).getTime() < new Date(archivedAt).getTime()) {
    throw new EvidenceValidationError('The notary challenge retention date cannot precede archival.', { field: 'retentionUntil' });
  }
  return {
    tenantId: identifier(input.tenantId, 'tenantId'),
    archiveId: archiveIdentifier(input.archiveId),
    receiptSha256: hashValue(input.receiptSha256, 'receiptSha256'),
    objectEnvelopeSha256: hashValue(input.objectEnvelopeSha256, 'objectEnvelopeSha256'),
    archivedAt,
    retentionUntil
  };
}

function jobIdFor(challenge, providerId) {
  return `NTR-${sha256([
    challenge.tenantId,
    challenge.archiveId,
    providerId,
    challenge.receiptSha256,
    challenge.objectEnvelopeSha256
  ].join('|')).slice(0, 32)}`;
}

function publicChallenge(job) {
  return {
    tenantId: job.tenantId,
    archiveId: job.archiveId,
    receiptSha256: job.receiptSha256,
    objectEnvelopeSha256: job.objectEnvelopeSha256,
    archivedAt: job.archivedAt,
    retentionUntil: job.retentionUntil
  };
}

function publicJob(job) {
  return {
    jobId: job.jobId,
    providerId: job.providerId,
    archiveId: job.archiveId,
    state: job.state,
    createdAt: job.createdAt,
    updatedAt: job.updatedAt,
    expiresAt: job.expiresAt,
    attempts: job.attempts,
    nextAttemptAt: job.nextAttemptAt,
    claimedAt: job.claimedAt,
    claimExpiresAt: job.claimExpiresAt,
    deliveredAt: job.deliveredAt,
    completedAt: job.completedAt,
    deadLetteredAt: job.deadLetteredAt,
    queuedBy: job.queuedBy,
    purpose: job.purpose,
    result: job.result,
    hash: job.hash
  };
}

function stateCounts(jobs) {
  const counts = { pending: 0, inflight: 0, delivered: 0, completed: 0, 'dead-letter': 0 };
  for (const job of jobs) counts[job.state] += 1;
  return { pending: counts.pending, inflight: counts.inflight, delivered: counts.delivered, completed: counts.completed, deadLetters: counts['dead-letter'] };
}

function hashJob(job) { return { ...withoutHash(job), hash: jobHash(job) }; }
function withoutHash(job) { const { hash, ...body } = job; return body; }
function jobHash(job) { return sha256(stableStringify(withoutHash(job))); }
function eventHash(event) { const { hash, ...body } = event; return sha256(stableStringify(body)); }
function indexAad(providerId) { return `basitclaw:evidence-notary-requests:${providerId}`; }
function safeJobId(value) { const id = String(value ?? ''); if (!JOB_ID.test(id)) throw new EvidenceValidationError('jobId is invalid.', { field: 'jobId' }); return id; }
function archiveIdentifier(value) { const id = String(value ?? ''); if (!ARCHIVE_ID.test(id)) throw new EvidenceValidationError('archiveId is invalid.', { field: 'archiveId' }); return id; }
function providerIdentifier(value) { return identifier(value, 'providerId'); }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function reasonIdentifier(value) { const text = String(value ?? ''); if (!REASON.test(text)) throw new EvidenceValidationError('reasonCode is invalid.', { field: 'reasonCode' }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new EvidenceValidationError(`${field} must be true or false.`, { field }); return value; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function strictObject(input, allowedFields, label) { if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError(`A valid ${label} is required.`); for (const key of Object.keys(input)) if (!allowedFields.has(key)) throw new EvidenceValidationError(`Unsupported ${label} field ${key}.`, { field: key }); return input; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }

function disabledOutbox() {
  const status = Object.freeze({ status: 'disabled', enabled: false, required: false, mode: 'disabled' });
  return Object.freeze({
    mode: 'disabled', enabled: false, required: false, providerIds: Object.freeze([]),
    queue() { throw new EvidenceConflictError('Evidence-notary request delivery is disabled.'); },
    requeue() { throw new EvidenceConflictError('Evidence-notary request delivery is disabled.'); },
    claimSigned() { throw new EvidenceConflictError('Evidence-notary request delivery is disabled.'); },
    acknowledgeSigned() { throw new EvidenceConflictError('Evidence-notary request delivery is disabled.'); },
    failSigned() { throw new EvidenceConflictError('Evidence-notary request delivery is disabled.'); },
    completeFromAttestation() { return { matched: false }; },
    list() { return []; },
    verifyTenant(tenantId) { return { valid: true, tenantId, checkedJobs: 0, checkedEvents: 0 }; },
    tenantStatus() { return status; },
    health() { return status; }
  });
}
