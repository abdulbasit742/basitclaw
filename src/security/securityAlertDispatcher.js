import {
  backoffDelayMs,
  createSecurityAlertCodec,
  retryAfterDelayMs,
  validateWebhookEndpoint
} from './securityAlertCodec.js';
import { createSecurityAlertOutbox } from './securityAlertOutbox.js';

export class SecurityAlertDeliveryError extends Error {
  constructor(message = 'The security alert delivery control is unavailable.', details = {}) {
    super(message);
    this.name = 'SecurityAlertDeliveryError';
    this.code = 'SECURITY_ALERT_DELIVERY_UNAVAILABLE';
    this.details = details;
  }
}

export function createSecurityAlertDispatcher({
  endpoint,
  signingSecret,
  outboxDirectory,
  required = false,
  minimumSeverity = 'high',
  includedTypes = [],
  maxAttempts = 8,
  baseDelayMs = 1_000,
  maxDelayMs = 300_000,
  timeoutMs = 5_000,
  pollIntervalMs = 5_000,
  batchSize = 25,
  allowHttp = process.env.NODE_ENV !== 'production',
  allowPrivateTargets = false,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
  outbox = null
} = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('A fetch implementation is required for security alert delivery.');
  const safeEndpoint = validateWebhookEndpoint(endpoint, { allowHttp, allowPrivateTargets });
  const codec = createSecurityAlertCodec({ signingSecret, minimumSeverity, includedTypes });
  const queue = outbox ?? createSecurityAlertOutbox({ directory: outboxDirectory, now });
  const safeMaxAttempts = integer(maxAttempts, 'maxAttempts', 1, 100);
  const safeBaseDelayMs = integer(baseDelayMs, 'baseDelayMs', 100, 3_600_000);
  const safeMaxDelayMs = integer(maxDelayMs, 'maxDelayMs', safeBaseDelayMs, 86_400_000);
  const safeTimeoutMs = integer(timeoutMs, 'timeoutMs', 100, 120_000);
  const safePollIntervalMs = integer(pollIntervalMs, 'pollIntervalMs', 1_000, 3_600_000);
  const safeBatchSize = integer(batchSize, 'batchSize', 1, 500);
  let timer = null;
  let running = false;
  let lastCycleAt = null;
  let lastSuccessAt = null;
  let lastError = null;
  let delivered = 0;
  let failed = 0;

  function enqueue(event) {
    if (!codec.shouldDeliver(event)) return { enqueued: false, filtered: true, reason: 'policy' };
    try {
      const result = queue.enqueue(event);
      lastError = null;
      return { ...result, filtered: false };
    } catch (error) {
      lastError = error.message;
      throw new SecurityAlertDeliveryError('The security alert could not be written to the durable outbox.', {
        cause: error.code ?? error.message
      });
    }
  }

  async function dispatchDue({ limit = safeBatchSize } = {}) {
    if (running) {
      return { skipped: true, reason: 'cycle_running', claimed: 0, delivered: 0, retried: 0, deadLettered: 0 };
    }
    running = true;
    const summary = { skipped: false, claimed: 0, delivered: 0, retried: 0, deadLettered: 0 };
    try {
      const claims = queue.claimDue({ limit });
      summary.claimed = claims.length;
      for (const claim of claims) {
        const outcome = await deliverClaim(claim);
        summary[outcome] += 1;
      }
      lastCycleAt = now().toISOString();
      lastError = null;
      return summary;
    } catch (error) {
      lastCycleAt = now().toISOString();
      lastError = error.message;
      throw new SecurityAlertDeliveryError('The security alert dispatch cycle failed.', {
        cause: error.code ?? error.message
      });
    } finally {
      running = false;
    }
  }

  async function deliverClaim(claim) {
    const emittedAt = now();
    const payload = codec.payload(claim, emittedAt);
    const body = JSON.stringify(payload);
    const headers = codec.headers(body, claim.deliveryId, emittedAt);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), safeTimeoutMs);
    timeout.unref?.();
    try {
      const response = await fetchImpl(safeEndpoint, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
        redirect: 'error'
      });
      if (response.status >= 200 && response.status < 300) {
        queue.complete(claim.deliveryId, claim.claimToken, {
          status: response.status,
          responseId: response.headers?.get?.('x-request-id') ?? response.headers?.get?.('x-event-id')
        });
        delivered += 1;
        lastSuccessAt = now().toISOString();
        return 'delivered';
      }
      const retryable = response.status === 408
        || response.status === 425
        || response.status === 429
        || response.status >= 500;
      return finaliseFailure(claim, {
        retryable,
        status: response.status,
        error: `Webhook returned HTTP ${response.status}.`,
        retryAfter: response.headers?.get?.('retry-after')
      });
    } catch (error) {
      return finaliseFailure(claim, {
        retryable: true,
        status: null,
        error: error?.name === 'AbortError' ? 'Webhook request timed out.' : error.message
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  function finaliseFailure(claim, { retryable, status, error, retryAfter = null }) {
    failed += 1;
    const nextAttemptNumber = claim.attempts + 1;
    if (retryable && nextAttemptNumber < safeMaxAttempts) {
      const serverDelay = retryAfterDelayMs(retryAfter, now(), safeMaxDelayMs);
      const delayMs = serverDelay ?? backoffDelayMs({
        deliveryId: claim.deliveryId,
        attempt: nextAttemptNumber,
        baseDelayMs: safeBaseDelayMs,
        maxDelayMs: safeMaxDelayMs
      });
      queue.retry(claim.deliveryId, claim.claimToken, {
        nextAttemptAt: new Date(now().getTime() + delayMs),
        status,
        error
      });
      return 'retried';
    }
    queue.deadLetter(claim.deliveryId, claim.claimToken, {
      status,
      error,
      reason: retryable ? 'maximum_attempts_exceeded' : 'non_retryable_response'
    });
    return 'deadLettered';
  }

  function start() {
    if (timer) return false;
    timer = setInterval(() => {
      dispatchDue().catch((error) => { lastError = error.message; });
    }, safePollIntervalMs);
    timer.unref?.();
    return true;
  }

  function stop() {
    if (!timer) return false;
    clearInterval(timer);
    timer = null;
    return true;
  }

  function health() {
    const outboxHealth = queue.health();
    const unhealthy = outboxHealth.status === 'unavailable' || (required && outboxHealth.status !== 'ready');
    return {
      status: unhealthy ? 'unavailable' : outboxHealth.status,
      enabled: true,
      required: Boolean(required),
      mode: 'signed-webhook-durable-outbox',
      endpointOrigin: new URL(safeEndpoint).origin,
      minimumSeverity: codec.minimumSeverity,
      includedTypes: codec.includedTypes,
      maxAttempts: safeMaxAttempts,
      timeoutMs: safeTimeoutMs,
      pollIntervalMs: safePollIntervalMs,
      running,
      schedulerStarted: Boolean(timer),
      delivered,
      failed,
      lastCycleAt,
      lastSuccessAt,
      lastError,
      outbox: outboxHealth
    };
  }

  return {
    enabled: true,
    required: Boolean(required),
    enqueue,
    dispatchDue,
    listDeadLetters: queue.listDeadLetters,
    requeue: queue.requeue,
    start,
    stop,
    health,
    verifySignature: codec.verify
  };
}

export function createDisabledSecurityAlertDispatcher({ required = false } = {}) {
  if (required) throw new TypeError('Required security alert delivery cannot be disabled.');
  return {
    enabled: false,
    required: false,
    enqueue: () => ({ enqueued: false, filtered: true, reason: 'disabled' }),
    dispatchDue: async () => ({
      skipped: true,
      reason: 'disabled',
      claimed: 0,
      delivered: 0,
      retried: 0,
      deadLettered: 0
    }),
    listDeadLetters: () => [],
    requeue: () => { throw new SecurityAlertDeliveryError('Security alert delivery is disabled.'); },
    start: () => false,
    stop: () => false,
    health: () => ({ status: 'disabled', enabled: false, required: false, mode: 'disabled' })
  };
}

export function createSecurityAlertDispatcherFromEnvironment(env = process.env, options = {}) {
  const mode = String(env.WORKFORCE_AUDIT_SECURITY_ALERT_MODE ?? 'disabled');
  const required = String(env.WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED ?? 'false') === 'true';
  if (!['disabled', 'webhook'].includes(mode)) {
    throw new TypeError('WORKFORCE_AUDIT_SECURITY_ALERT_MODE must be disabled or webhook.');
  }
  if (mode === 'disabled') return createDisabledSecurityAlertDispatcher({ required });
  return createSecurityAlertDispatcher({
    endpoint: env.WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL,
    signingSecret: env.WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET,
    outboxDirectory: env.WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR
      ?? '.runtime-data/workforce-audit-security-alerts',
    required,
    minimumSeverity: env.WORKFORCE_AUDIT_SECURITY_ALERT_MIN_SEVERITY ?? 'high',
    includedTypes: env.WORKFORCE_AUDIT_SECURITY_ALERT_TYPES ?? '',
    maxAttempts: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_MAX_ATTEMPTS ?? 8),
    baseDelayMs: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_BASE_DELAY_MS ?? 1_000),
    maxDelayMs: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_MAX_DELAY_MS ?? 300_000),
    timeoutMs: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_TIMEOUT_MS ?? 5_000),
    pollIntervalMs: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_POLL_INTERVAL_MS ?? 5_000),
    batchSize: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_BATCH_SIZE ?? 25),
    allowHttp: String(env.WORKFORCE_AUDIT_SECURITY_ALERT_ALLOW_HTTP ?? (env.NODE_ENV !== 'production')) === 'true',
    allowPrivateTargets: String(env.WORKFORCE_AUDIT_SECURITY_ALERT_ALLOW_PRIVATE_TARGETS ?? 'false') === 'true',
    ...options
  });
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}
