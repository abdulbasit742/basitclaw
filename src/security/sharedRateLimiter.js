import { createHash, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { createFileMutex, SecurityControlBusyError, SecurityControlUnavailableError } from './fileMutex.js';

export class RateLimitStoreError extends Error {
  constructor(message = 'The shared rate-limit store is unavailable.', details = {}) {
    super(message);
    this.name = 'RateLimitStoreError';
    this.code = 'RATE_LIMIT_STORE_UNAVAILABLE';
    this.details = details;
  }
}

export function createSharedFileRateLimiter({
  directory,
  policies,
  trustProxyHops = 0,
  resolveClientAddress,
  now = () => new Date(),
  mutex = null,
  maxBuckets = 100_000,
  cleanupIntervalMs = 300_000,
  lockLeaseMs = 5_000,
  lockAcquireTimeoutMs = 1_000,
  lockRetryMs = 10,
  required = true
} = {}) {
  if (!String(directory ?? '').trim()) throw new TypeError('A shared rate-limit directory is required.');
  if (typeof resolveClientAddress !== 'function') throw new TypeError('A client-address resolver is required.');
  const root = resolve(String(directory));
  const bucketDirectory = resolve(root, 'buckets');
  const safePolicies = normalisePolicies(policies);
  const bucketLimit = integer(maxBuckets, 'maxBuckets', 100, 1_000_000);
  const cleanupEvery = integer(cleanupIntervalMs, 'cleanupIntervalMs', 1_000, 86_400_000);
  mkdirSync(bucketDirectory, { recursive: true, mode: 0o700 });
  const lock = mutex ?? createFileMutex({
    directory: resolve(root, 'locks'),
    leaseMs: lockLeaseMs,
    acquireTimeoutMs: lockAcquireTimeoutMs,
    retryMs: lockRetryMs,
    now
  });
  let lastCleanupAt = 0;
  let lastError = null;

  function consume(identity, policyName) {
    const policy = safePolicies[policyName];
    if (!policy) throw new TypeError(`Unknown rate-limit policy: ${policyName}`);
    const identityHash = createHash('sha256').update(`${policyName}:${String(identity)}`).digest('hex');
    const path = resolve(bucketDirectory, `${identityHash}.json`);
    try {
      const updateBucket = () => lock.withLock(`rate:${identityHash}`, () => {
        const currentMs = now().getTime();
        const windowStart = Math.floor(currentMs / policy.windowMs) * policy.windowMs;
        const existing = readBucket(path, policyName, identityHash);
        const count = existing && existing.windowStart === windowStart ? existing.count + 1 : 1;
        const state = { version: 1, policy: policyName, identityHash, windowStart, count, lastSeenAt: currentMs };
        atomicWriteJson(path, state);
        const resetAt = windowStart + policy.windowMs;
        return {
          allowed: count <= policy.limit,
          policy: policyName,
          limit: policy.limit,
          remaining: Math.max(0, policy.limit - count),
          resetAt: new Date(resetAt).toISOString(),
          retryAfterSeconds: Math.max(1, Math.ceil((resetAt - currentMs) / 1000)),
          distributed: true
        };
      });
      const decision = existsSync(path)
        ? updateBucket()
        : lock.withLock('rate-capacity', () => {
          pruneExpired(now().getTime());
          const activeBuckets = readdirSync(bucketDirectory).filter((name) => name.endsWith('.json')).length;
          if (activeBuckets >= bucketLimit) {
            throw new RateLimitStoreError('The shared rate-limit bucket capacity has been reached.', { maxBuckets: bucketLimit });
          }
          return updateBucket();
        });
      lastError = null;
      maybeCleanup();
      return decision;
    } catch (error) {
      lastError = error.message;
      throw wrapStoreError(error, policyName);
    }
  }

  function headers(decision) {
    if (!decision || decision.limit === null) return {};
    return {
      'ratelimit-limit': String(decision.limit),
      'ratelimit-remaining': String(decision.remaining),
      'ratelimit-reset': String(Math.ceil(new Date(decision.resetAt).getTime() / 1000))
    };
  }

  function health() {
    try {
      mkdirSync(bucketDirectory, { recursive: true, mode: 0o700 });
      const probe = resolve(bucketDirectory, `.probe-${randomUUID()}`);
      writeFileSync(probe, 'probe', { mode: 0o600, flag: 'wx' });
      rmSync(probe, { force: true });
      const activeBuckets = readdirSync(bucketDirectory).filter((name) => name.endsWith('.json')).length;
      return {
        status: lastError ? 'degraded' : 'ready',
        enabled: true,
        mode: 'shared-file-fixed-window',
        distributed: true,
        required: Boolean(required),
        directory: root,
        trustProxyHops: Number(trustProxyHops),
        activeBuckets,
        maxBuckets: bucketLimit,
        policies: structuredClone(safePolicies),
        mutex: lock.health(),
        error: lastError
      };
    } catch (error) {
      return {
        status: 'unavailable', enabled: true, mode: 'shared-file-fixed-window', distributed: true, required: Boolean(required),
        directory: root, trustProxyHops: Number(trustProxyHops), activeBuckets: null,
        maxBuckets: bucketLimit, policies: structuredClone(safePolicies), error: error.message
      };
    }
  }

  function clientAddress(req) {
    return resolveClientAddress(req, trustProxyHops);
  }

  function maybeCleanup() {
    const currentMs = now().getTime();
    if (currentMs - lastCleanupAt < cleanupEvery) return;
    lastCleanupAt = currentMs;
    try {
      lock.withLock('rate-cleanup', () => pruneExpired(currentMs));
    } catch { /* cleanup is opportunistic; consume already committed safely */ }
  }

  function pruneExpired(currentMs) {
    const longestWindow = Math.max(...Object.values(safePolicies).map((policy) => policy.windowMs));
    const candidates = [];
    for (const name of readdirSync(bucketDirectory)) {
      if (!name.endsWith('.json')) continue;
      const path = resolve(bucketDirectory, name);
      try {
        const state = JSON.parse(readFileSync(path, 'utf8'));
        if (currentMs - Number(state.lastSeenAt) > longestWindow * 2) candidates.push({ path, lastSeenAt: Number(state.lastSeenAt) });
      } catch { /* corrupt files remain visible and fail closed when consumed */ }
    }
    candidates.sort((a, b) => a.lastSeenAt - b.lastSeenAt);
    for (const candidate of candidates) {
      const identityHash = basename(candidate.path).replace(/\.json$/, '');
      lock.withLock(`rate:${identityHash}`, () => {
        if (!existsSync(candidate.path)) return;
        try {
          const state = JSON.parse(readFileSync(candidate.path, 'utf8'));
          if (currentMs - Number(state.lastSeenAt) > longestWindow * 2) rmSync(candidate.path, { force: true });
        } catch { /* corrupt buckets remain fail-closed evidence */ }
      });
    }
  }

  return { consume, headers, health, clientAddress, policies: structuredClone(safePolicies), directory: root };
}

function readBucket(path, policyName, identityHash) {
  if (!existsSync(path)) return null;
  let state;
  try { state = JSON.parse(readFileSync(path, 'utf8')); } catch (error) {
    throw new RateLimitStoreError('A shared rate-limit bucket could not be decoded.', { policy: policyName, cause: error.message });
  }
  if (state?.version !== 1 || state.policy !== policyName || state.identityHash !== identityHash
      || !Number.isInteger(state.count) || !Number.isFinite(state.windowStart)) {
    throw new RateLimitStoreError('A shared rate-limit bucket failed validation.', { policy: policyName });
  }
  return state;
}

function atomicWriteJson(path, value) {
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  const descriptor = openSync(temporary, 'wx', 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  const directoryDescriptor = openSync(dirname(path), 'r');
  try { fsyncSync(directoryDescriptor); } finally { closeSync(directoryDescriptor); }
}

function wrapStoreError(error, policy) {
  if (error instanceof RateLimitStoreError) return error;
  if (error instanceof SecurityControlBusyError || error instanceof SecurityControlUnavailableError) {
    return new RateLimitStoreError('The shared rate-limit bucket could not be updated safely.', { policy, cause: error.code });
  }
  return new RateLimitStoreError('The shared rate-limit filesystem operation failed.', { policy, cause: error?.code ?? error?.message });
}

function normalisePolicies(policies) {
  const result = {};
  for (const [name, policy] of Object.entries(policies ?? {})) {
    result[name] = {
      limit: integer(policy.limit, `${name}.limit`, 1, 1_000_000),
      windowMs: integer(policy.windowMs, `${name}.windowMs`, 1_000, 86_400_000)
    };
  }
  for (const required of ['burst', 'authFailure', 'read', 'write', 'sensitive']) {
    if (!result[required]) throw new TypeError(`Missing rate-limit policy: ${required}`);
  }
  return Object.freeze(result);
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}
