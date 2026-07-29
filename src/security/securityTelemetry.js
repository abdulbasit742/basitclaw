import { createHash, randomBytes } from 'node:crypto';
import { createSecurityAlertRuntimeFromEnvironment } from './securityAlertRuntime.js';

export function createSecurityTelemetry({
  now = () => new Date(),
  pepper = randomBytes(32).toString('base64'),
  maxEvents = 2000,
  ephemeralPepper = false,
  archive = null,
  alertDispatcher = null
} = {}) {
  const limit = normaliseInteger(maxEvents, 'maxEvents', 100, 100_000);
  const safePepper = String(pepper ?? '');
  if (safePepper.length < 16) throw new TypeError('Security telemetry pepper must contain at least 16 characters.');
  const events = [];
  let sequence = 0;
  let archiveFailures = 0;
  let lastArchiveError = null;
  let alertEnqueueFailures = 0;
  let lastAlertError = null;

  function record(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('Security event input must be an object.');
    const previousHash = events.at(-1)?.hash ?? null;
    const unsigned = {
      id: `SEC-${String(++sequence).padStart(10, '0')}`,
      sequence,
      occurredAt: now().toISOString(),
      type: safeIdentifier(input.type, 'type'),
      severity: normaliseSeverity(input.severity),
      outcome: safeIdentifier(input.outcome ?? 'observed', 'outcome'),
      requestId: nullableIdentifier(input.requestId),
      ipFingerprint: fingerprint(input.clientAddress),
      keyId: nullableIdentifier(input.keyId),
      subject: nullableIdentifier(input.subject),
      tenantId: nullableIdentifier(input.tenantId),
      method: input.method ? String(input.method).toUpperCase().slice(0, 16) : null,
      route: input.route ? String(input.route).slice(0, 256) : null,
      details: sanitise(input.details ?? {}),
      previousHash
    };
    const event = Object.freeze({ ...unsigned, hash: hashValue(unsigned) });
    events.push(event);
    while (events.length > limit) events.shift();
    if (archive?.enabled) {
      try {
        archive.append(event);
        lastArchiveError = null;
      } catch (error) {
        archiveFailures += 1;
        lastArchiveError = error.message;
      }
    }
    if (alertDispatcher?.enabled) {
      try {
        alertDispatcher.enqueue(event);
        lastAlertError = null;
      } catch (error) {
        alertEnqueueFailures += 1;
        lastAlertError = error.message;
      }
    }
    return structuredClone(event);
  }

  function list({ limit: requestedLimit = 100, type = null, severity = null } = {}) {
    const safeLimit = normaliseInteger(requestedLimit, 'limit', 1, 500);
    return events
      .filter((event) => !type || event.type === type)
      .filter((event) => !severity || event.severity === severity)
      .slice(-safeLimit)
      .reverse()
      .map((event) => structuredClone(event));
  }

  function verify() {
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index];
      const { hash, ...unsigned } = event;
      if (hashValue(unsigned) !== hash) {
        return { valid: false, retainedEvents: events.length, failedEventId: event.id, headHash: events.at(-1)?.hash ?? null };
      }
      if (index > 0 && event.previousHash !== events[index - 1].hash) {
        return { valid: false, retainedEvents: events.length, failedEventId: event.id, headHash: events.at(-1)?.hash ?? null };
      }
    }
    return { valid: true, retainedEvents: events.length, failedEventId: null, headHash: events.at(-1)?.hash ?? null };
  }

  function summary() {
    const countsByType = {};
    const countsBySeverity = {};
    for (const event of events) {
      countsByType[event.type] = (countsByType[event.type] ?? 0) + 1;
      countsBySeverity[event.severity] = (countsBySeverity[event.severity] ?? 0) + 1;
    }
    const archiveHealth = archive?.health?.() ?? {
      status: 'disabled', enabled: false, required: false, mode: 'disabled', durable: false, distributed: false
    };
    const alertHealth = alertDispatcher?.health?.() ?? {
      status: 'disabled', enabled: false, required: false, mode: 'disabled'
    };
    const archiveFailure = archiveHealth.required && archiveHealth.status !== 'ready';
    const alertFailure = alertHealth.required && alertHealth.status !== 'ready';
    const evidenceRequired = Boolean(archiveHealth.required || alertHealth.required);
    const evidenceStatus = archiveFailure || alertFailure
      ? 'unavailable'
      : evidenceRequired ? 'ready' : archiveHealth.status;
    return {
      status: archiveFailure || alertFailure ? 'unavailable' : 'ready',
      mode: archiveHealth.enabled ? 'bounded-memory-plus-encrypted-archive' : 'bounded-memory-hash-chain',
      durable: Boolean(archiveHealth.enabled && archiveHealth.durable),
      distributed: Boolean(archiveHealth.enabled && archiveHealth.distributed),
      ephemeralPepper,
      retainedEvents: events.length,
      maxEvents: limit,
      lastEventAt: events.at(-1)?.occurredAt ?? null,
      countsByType,
      countsBySeverity,
      integrity: verify(),
      archive: {
        ...archiveHealth,
        status: evidenceStatus,
        required: evidenceRequired,
        archiveOnlyStatus: archiveHealth.status,
        failures: archiveFailures,
        lastError: lastArchiveError
      },
      alertDelivery: {
        ...alertHealth,
        enqueueFailures: alertEnqueueFailures,
        lastEnqueueError: lastAlertError
      }
    };
  }

  function fingerprint(value) {
    return createHash('sha256').update(`${safePepper}:${String(value ?? 'unknown')}`).digest('hex').slice(0, 24);
  }

  function listArchived(options) {
    return archive?.list?.(options) ?? {
      events: [], anchorSequence: 0, headSequence: 0, nextSequence: options?.afterSequence ?? 0
    };
  }

  function verifyArchive() {
    return archive?.verify?.() ?? {
      valid: true, disabled: true, retainedEvents: 0, headSequence: 0, headHash: null
    };
  }

  return { record, list, verify, summary, fingerprint, listArchived, verifyArchive };
}

export function createSecurityTelemetryFromEnvironment(
  env = process.env,
  { archive = null, alertDispatcher = null } = {}
) {
  const configuredPepper = env.WORKFORCE_AUDIT_SECURITY_EVENT_PEPPER;
  const delivery = alertDispatcher ?? createSecurityAlertRuntimeFromEnvironment(env);
  return createSecurityTelemetry({
    pepper: configuredPepper ?? randomBytes(32).toString('base64'),
    ephemeralPepper: !configuredPepper,
    maxEvents: Number(env.WORKFORCE_AUDIT_SECURITY_EVENT_RETENTION ?? 2000),
    archive,
    alertDispatcher: delivery
  });
}

function hashValue(value) {
  return createHash('sha256').update(stableStringify(value)).digest('hex');
}

function normaliseSeverity(value = 'info') {
  const severity = String(value);
  if (!['info', 'warning', 'high', 'critical'].includes(severity)) throw new TypeError('Security event severity is invalid.');
  return severity;
}

function safeIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(identifier)) {
    throw new TypeError(`${field} must be a safe security-event identifier.`);
  }
  return identifier;
}

function nullableIdentifier(value) {
  if (value === undefined || value === null || value === '') return null;
  const identifier = String(value).trim();
  return /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(identifier) ? identifier : null;
}

function sanitise(value, depth = 0) {
  if (depth > 4) return '[depth-limited]';
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    return typeof value === 'string' ? value.slice(0, 500) : value;
  }
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitise(item, depth + 1));
  if (typeof value === 'object') {
    const output = {};
    for (const [key, item] of Object.entries(value).slice(0, 50)) {
      if (/api.?key|secret|token|password|address|ip/i.test(key)) continue;
      output[key] = sanitise(item, depth + 1);
    }
    return output;
  }
  return String(value).slice(0, 500);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normaliseInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}
