import { scryptSync, timingSafeEqual } from 'node:crypto';

const STATUSES = new Set(['active', 'retiring', 'revoked']);
const SCOPES = new Set(['scim:read', 'scim:write']);

export class ScimAuthenticationError extends Error {
  constructor(message = 'A valid SCIM bearer credential is required.', code = 'SCIM_UNAUTHENTICATED', details = {}) {
    super(message);
    this.name = 'ScimAuthenticationError';
    this.code = code;
    this.details = details;
  }
}

export class ScimAuthorizationError extends Error {
  constructor(message = 'The SCIM principal is not authorised for this operation.', details = {}) {
    super(message);
    this.name = 'ScimAuthorizationError';
    this.code = 'SCIM_FORBIDDEN';
    this.details = details;
  }
}

export function createScimAccessController({ credentials, now = () => new Date() } = {}) {
  const records = normaliseCredentials(credentials);

  function authenticate(req) {
    const token = bearerToken(req?.headers?.authorization);
    const separator = token.indexOf('.');
    if (separator < 2) throw new ScimAuthenticationError(undefined, 'SCIM_CREDENTIAL_INVALID');
    const keyId = token.slice(0, separator);
    const secret = token.slice(separator + 1);
    const record = records.find((item) => item.keyId === keyId);
    if (!record || !verify(record, secret)) throw new ScimAuthenticationError(undefined, 'SCIM_CREDENTIAL_INVALID', { keyId });
    const current = now();
    if (record.status === 'revoked') throw new ScimAuthenticationError('The SCIM credential has been revoked.', 'SCIM_CREDENTIAL_REVOKED', { keyId });
    if (record.notBefore && current < record.notBefore) throw new ScimAuthenticationError('The SCIM credential is not active yet.', 'SCIM_CREDENTIAL_NOT_ACTIVE', { keyId });
    if (record.expiresAt && current >= record.expiresAt) throw new ScimAuthenticationError('The SCIM credential has expired.', 'SCIM_CREDENTIAL_EXPIRED', { keyId });
    return Object.freeze({
      keyId: record.keyId,
      subject: record.subject,
      scopes: [...record.scopes],
      status: record.status,
      expiresAt: record.expiresAt?.toISOString() ?? null
    });
  }

  function authorise(principal, scope) {
    if (!principal?.scopes?.includes(scope)) throw new ScimAuthorizationError(undefined, { scope, keyId: principal?.keyId ?? null });
    return principal;
  }

  function health() {
    const current = now();
    const usable = records.filter((item) => item.status !== 'revoked'
      && (!item.notBefore || current >= item.notBefore)
      && (!item.expiresAt || current < item.expiresAt));
    return {
      status: usable.length > 0 ? 'ready' : 'unavailable',
      enabled: true,
      total: records.length,
      usable: usable.length,
      retiring: usable.filter((item) => item.status === 'retiring').length,
      nextExpiryAt: usable.map((item) => item.expiresAt).filter(Boolean).sort((a, b) => a - b)[0]?.toISOString() ?? null
    };
  }

  return { authenticate, authorise, health, credentialCount: records.length };
}

export function createScimAccessControllerFromEnvironment(env = process.env, options = {}) {
  const raw = env.WORKFORCE_AUDIT_SCIM_CREDENTIALS;
  if (!raw) throw new TypeError('WORKFORCE_AUDIT_SCIM_CREDENTIALS is required when SCIM provisioning is enabled.');
  let credentials;
  try { credentials = JSON.parse(raw); } catch { throw new TypeError('WORKFORCE_AUDIT_SCIM_CREDENTIALS must contain valid JSON.'); }
  return createScimAccessController({ credentials, ...options });
}

function normaliseCredentials(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) throw new TypeError('SCIM credentials must contain from 1 to 50 records.');
  const ids = new Set();
  return value.map((item, index) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) throw new TypeError(`SCIM credential at index ${index} must be an object.`);
    const keyId = safeIdentifier(item.keyId, 'keyId');
    if (ids.has(keyId)) throw new TypeError('Duplicate SCIM credential key IDs are not allowed.');
    ids.add(keyId);
    const subject = safeIdentifier(item.subject, 'subject');
    const salt = String(item.salt ?? '');
    const secretHash = String(item.secretHash ?? '');
    if (salt.length < 16) throw new TypeError(`SCIM credential ${keyId} has an invalid salt.`);
    const decoded = Buffer.from(secretHash, 'base64');
    if (decoded.length !== 32 || decoded.toString('base64') !== secretHash) throw new TypeError(`SCIM credential ${keyId} has an invalid secretHash.`);
    const status = String(item.status ?? 'active');
    if (!STATUSES.has(status)) throw new TypeError(`SCIM credential ${keyId} has an unsupported status.`);
    const scopes = [...new Set((Array.isArray(item.scopes) ? item.scopes : ['scim:read', 'scim:write']).map(String))];
    if (scopes.length === 0 || scopes.some((scope) => !SCOPES.has(scope))) throw new TypeError(`SCIM credential ${keyId} has invalid scopes.`);
    const notBefore = optionalDate(item.notBefore, 'notBefore');
    const expiresAt = optionalDate(item.expiresAt, 'expiresAt');
    if (notBefore && expiresAt && expiresAt <= notBefore) throw new TypeError(`SCIM credential ${keyId} expiresAt must be after notBefore.`);
    return Object.freeze({ keyId, subject, salt, secretHash, status, scopes, notBefore, expiresAt });
  });
}

function bearerToken(value) {
  const header = Array.isArray(value) ? value[0] : value;
  const match = String(header ?? '').trim().match(/^Bearer\s+([^\s]+)$/i);
  if (!match) throw new ScimAuthenticationError();
  if (match[1].length > 4096) throw new ScimAuthenticationError('The SCIM bearer credential is malformed.', 'SCIM_CREDENTIAL_INVALID');
  return match[1];
}

function verify(record, secret) {
  try {
    const expected = Buffer.from(record.secretHash, 'base64');
    const actual = scryptSync(secret, record.salt, expected.length);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}

function optionalDate(value, field) {
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError(`${field} must be a valid date.`);
  return date;
}

function safeIdentifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(text)) throw new TypeError(`${field} must be a safe identifier.`);
  return text;
}
