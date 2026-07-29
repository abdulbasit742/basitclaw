import { createHash } from 'node:crypto';

const DEFAULT_POLICIES = Object.freeze({
  burst: { limit: 300, windowMs: 60_000 },
  authFailure: { limit: 8, windowMs: 300_000 },
  read: { limit: 240, windowMs: 60_000 },
  write: { limit: 60, windowMs: 60_000 },
  sensitive: { limit: 10, windowMs: 900_000 }
});

export class RateLimitError extends Error {
  constructor(message = 'The request rate limit has been exceeded.', decision = {}) {
    super(message);
    this.name = 'RateLimitError';
    this.code = 'RATE_LIMITED';
    this.details = decision;
  }
}

export function createAdaptiveRateLimiter({
  now = () => new Date(),
  policies = DEFAULT_POLICIES,
  enabled = true,
  trustProxyHops = 0,
  maxBuckets = 20_000
} = {}) {
  const safePolicies = normalisePolicies(policies);
  const buckets = new Map();
  const trustedHops = normaliseInteger(trustProxyHops, 'trustProxyHops', 0, 10);
  const bucketLimit = normaliseInteger(maxBuckets, 'maxBuckets', 100, 1_000_000);

  function consume(identity, policyName) {
    const policy = safePolicies[policyName];
    if (!policy) throw new TypeError(`Unknown rate-limit policy: ${policyName}`);
    const currentMs = now().getTime();
    if (!enabled) return decisionForDisabled(policyName, currentMs);
    const windowStart = Math.floor(currentMs / policy.windowMs) * policy.windowMs;
    const key = createHash('sha256').update(`${policyName}:${String(identity)}`).digest('hex');
    const existing = buckets.get(key);
    const entry = !existing || existing.windowStart !== windowStart
      ? { windowStart, count: 0, lastSeenAt: currentMs }
      : existing;
    entry.count += 1;
    entry.lastSeenAt = currentMs;
    buckets.set(key, entry);
    if (buckets.size > bucketLimit) pruneBuckets(currentMs);
    const resetAt = windowStart + policy.windowMs;
    return {
      allowed: entry.count <= policy.limit,
      policy: policyName,
      limit: policy.limit,
      remaining: Math.max(0, policy.limit - entry.count),
      resetAt: new Date(resetAt).toISOString(),
      retryAfterSeconds: Math.max(1, Math.ceil((resetAt - currentMs) / 1000))
    };
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
    return {
      status: enabled ? 'ready' : 'disabled',
      enabled,
      mode: enabled ? 'local-memory-fixed-window' : 'disabled',
      distributed: false,
      trustProxyHops: trustedHops,
      activeBuckets: buckets.size,
      policies: structuredClone(safePolicies)
    };
  }

  function clientAddress(req) {
    return resolveClientAddress(req, trustedHops);
  }

  function pruneBuckets(currentMs) {
    const ordered = [...buckets.entries()].sort((left, right) => left[1].lastSeenAt - right[1].lastSeenAt);
    const longestWindow = Math.max(...Object.values(safePolicies).map((policy) => policy.windowMs));
    for (const [key, entry] of ordered) {
      if (buckets.size <= Math.floor(bucketLimit * 0.9) && currentMs - entry.lastSeenAt <= longestWindow) break;
      buckets.delete(key);
    }
  }

  return { consume, headers, health, clientAddress, policies: structuredClone(safePolicies) };
}

export function createAdaptiveRateLimiterFromEnvironment(env = process.env) {
  const enabled = String(env.WORKFORCE_AUDIT_RATE_LIMIT_MODE ?? 'memory') !== 'disabled';
  return createAdaptiveRateLimiter({
    enabled,
    trustProxyHops: Number(env.WORKFORCE_AUDIT_TRUST_PROXY_HOPS ?? 0),
    policies: {
      burst: { limit: Number(env.WORKFORCE_AUDIT_RATE_LIMIT_BURST_PER_MINUTE ?? 300), windowMs: 60_000 },
      authFailure: { limit: Number(env.WORKFORCE_AUDIT_RATE_LIMIT_AUTH_FAILURES_PER_5_MINUTES ?? 8), windowMs: 300_000 },
      read: { limit: Number(env.WORKFORCE_AUDIT_RATE_LIMIT_READ_PER_MINUTE ?? 240), windowMs: 60_000 },
      write: { limit: Number(env.WORKFORCE_AUDIT_RATE_LIMIT_WRITE_PER_MINUTE ?? 60), windowMs: 60_000 },
      sensitive: { limit: Number(env.WORKFORCE_AUDIT_RATE_LIMIT_SENSITIVE_PER_15_MINUTES ?? 10), windowMs: 900_000 }
    }
  });
}

export function classifyRequest(method, pathname) {
  const verb = String(method ?? 'GET').toUpperCase();
  const path = String(pathname ?? '');
  if (verb !== 'GET' && (
    path.endsWith('/restore')
    || path.endsWith('/replicate')
    || path.endsWith('/recovery-drills')
    || path.endsWith('/resilience-cycle')
  )) return 'sensitive';
  return ['GET', 'HEAD', 'OPTIONS'].includes(verb) ? 'read' : 'write';
}

export function resolveClientAddress(req, trustProxyHops = 0) {
  const remote = normaliseAddress(req?.socket?.remoteAddress ?? req?.connection?.remoteAddress ?? 'unknown');
  const hops = normaliseInteger(trustProxyHops, 'trustProxyHops', 0, 10);
  if (hops === 0) return remote;
  const forwarded = String(req?.headers?.['x-forwarded-for'] ?? '')
    .split(',')
    .map((value) => normaliseAddress(value))
    .filter(Boolean);
  const chain = [...forwarded, remote];
  const index = Math.max(0, chain.length - hops - 1);
  return chain[index] ?? remote;
}

function normaliseAddress(value) {
  const address = String(value ?? '').trim();
  if (address.startsWith('::ffff:')) return address.slice(7);
  return address || 'unknown';
}

function normalisePolicies(policies) {
  const result = {};
  for (const [name, policy] of Object.entries(policies ?? {})) {
    result[name] = {
      limit: normaliseInteger(policy.limit, `${name}.limit`, 1, 1_000_000),
      windowMs: normaliseInteger(policy.windowMs, `${name}.windowMs`, 1000, 86_400_000)
    };
  }
  for (const required of Object.keys(DEFAULT_POLICIES)) {
    if (!result[required]) throw new TypeError(`Missing rate-limit policy: ${required}`);
  }
  return Object.freeze(result);
}

function normaliseInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}

function decisionForDisabled(policy, currentMs) {
  return { allowed: true, policy, limit: null, remaining: null, resetAt: new Date(currentMs).toISOString(), retryAfterSeconds: 0 };
}
