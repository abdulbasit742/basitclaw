import { createHmac, timingSafeEqual } from 'node:crypto';

const SEVERITY_RANK = Object.freeze({ info: 0, warning: 1, high: 2, critical: 3 });

export function createSecurityAlertCodec({ signingSecret, minimumSeverity = 'high', includedTypes = [] } = {}) {
  const secret = Buffer.from(String(signingSecret ?? ''), 'utf8');
  if (secret.length < 32) throw new TypeError('Security alert signing secret must contain at least 32 bytes.');
  const minimum = normaliseSeverity(minimumSeverity);
  const typeSet = new Set(normaliseTypes(includedTypes));

  function shouldDeliver(event) {
    if (!event || typeof event !== 'object' || Array.isArray(event)) return false;
    const severity = normaliseSeverity(event.severity);
    if (SEVERITY_RANK[severity] < SEVERITY_RANK[minimum]) return false;
    return typeSet.size === 0 || typeSet.has(String(event.type));
  }

  function payload(delivery, now = new Date()) {
    return {
      version: 1,
      deliveryId: delivery.deliveryId,
      emittedAt: now.toISOString(),
      attempt: delivery.attempts + 1,
      event: delivery.event
    };
  }

  function headers(body, deliveryId, timestamp = new Date()) {
    const bodyText = typeof body === 'string' ? body : JSON.stringify(body);
    const timestampSeconds = String(Math.floor(timestamp.getTime() / 1000));
    const signature = sign(`${timestampSeconds}.${bodyText}`);
    return {
      'content-type': 'application/json; charset=utf-8',
      'user-agent': 'BasitClaw-Security-Alerts/1.0',
      'x-basitclaw-delivery-id': deliveryId,
      'x-basitclaw-timestamp': timestampSeconds,
      'x-basitclaw-signature': `sha256=${signature}`
    };
  }

  function verify(body, timestampSeconds, signature) {
    const expected = `sha256=${sign(`${timestampSeconds}.${body}`)}`;
    return constantEqual(expected, signature);
  }

  function sign(value) {
    return createHmac('sha256', secret).update(String(value)).digest('hex');
  }

  return {
    minimumSeverity: minimum,
    includedTypes: [...typeSet],
    shouldDeliver,
    payload,
    headers,
    verify
  };
}

export function backoffDelayMs({ deliveryId, attempt, baseDelayMs, maxDelayMs }) {
  const safeAttempt = integer(attempt, 'attempt', 1, 100);
  const base = integer(baseDelayMs, 'baseDelayMs', 100, 3_600_000);
  const maximum = integer(maxDelayMs, 'maxDelayMs', base, 86_400_000);
  const exponential = Math.min(maximum, base * (2 ** Math.min(20, safeAttempt - 1)));
  const digest = createHmac('sha256', String(deliveryId)).update(String(safeAttempt)).digest();
  const jitterRatio = (digest.readUInt16BE(0) / 65535) * 0.2;
  return Math.min(maximum, Math.max(base, Math.round(exponential * (0.9 + jitterRatio))));
}

export function retryAfterDelayMs(value, now = new Date(), maximumMs = 86_400_000) {
  const raw = String(value ?? '').trim();
  if (!raw) return null;
  if (/^\d+$/.test(raw)) return Math.min(maximumMs, Number(raw) * 1000);
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return null;
  return Math.min(maximumMs, Math.max(0, date.getTime() - now.getTime()));
}

export function validateWebhookEndpoint(value, { allowHttp = false, allowPrivateTargets = false } = {}) {
  let url;
  try { url = new URL(String(value ?? '')); } catch { throw new TypeError('Security alert webhook URL must be valid.'); }
  if (!['https:', ...(allowHttp ? ['http:'] : [])].includes(url.protocol)) {
    throw new TypeError('Security alert webhook URL must use HTTPS.');
  }
  if (url.username || url.password) throw new TypeError('Security alert webhook URL must not contain user information.');
  if (!allowPrivateTargets && isPrivateHostname(url.hostname)) {
    throw new TypeError('Security alert webhook URL targets a private or local address.');
  }
  url.hash = '';
  return url.toString();
}

function normaliseSeverity(value) {
  const severity = String(value ?? '').toLowerCase();
  if (!(severity in SEVERITY_RANK)) throw new TypeError('Security alert severity is invalid.');
  return severity;
}

function normaliseTypes(values) {
  if (typeof values === 'string') values = values.split(',');
  if (!Array.isArray(values)) throw new TypeError('Security alert includedTypes must be an array or comma-separated string.');
  return values.map((value) => String(value).trim()).filter(Boolean).map((value) => {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(value)) throw new TypeError('Security alert event type is invalid.');
    return value;
  });
}

function isPrivateHostname(hostname) {
  const value = String(hostname).toLowerCase();
  if (value === 'localhost' || value.endsWith('.localhost') || value.endsWith('.local')) return true;
  if (value === '::1' || value === '[::1]') return true;
  const ipv4 = value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!ipv4) return false;
  const [a, b] = ipv4.slice(1).map(Number);
  return a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function constantEqual(left, right) {
  const a = Buffer.from(String(left ?? ''));
  const b = Buffer.from(String(right ?? ''));
  return a.length === b.length && timingSafeEqual(a, b);
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}
