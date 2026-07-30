import { createHash, scryptSync, timingSafeEqual } from 'node:crypto';

const ROLE_PERMISSIONS = Object.freeze({
  audit_viewer: ['audit:read'],
  auditor: ['audit:read', 'fieldwork:write', 'finding:write'],
  audit_manager: [
    'audit:read', 'engagement:write', 'fieldwork:write', 'finding:write', 'governance:read', 'evidence:scan', 'evidence:preserve', 'evidence:disclose',
    'backup:read', 'backup:write', 'replica:read', 'replica:write', 'resilience:read', 'drill:run',
    'coordination:read', 'privileged:request', 'privileged:read'
  ],
  compliance_admin: [
    'audit:read', 'engagement:write', 'fieldwork:write', 'finding:write', 'governance:read', 'evidence:scan', 'evidence:preserve', 'evidence:disclose',
    'backup:read', 'backup:write', 'backup:restore', 'replica:read', 'replica:write',
    'resilience:read', 'resilience:run', 'drill:run', 'coordination:read', 'security:read',
    'privileged:request', 'privileged:read', 'privileged:approve', 'privileged:revoke',
    'privileged:break_glass'
  ]
});

const CREDENTIAL_STATUSES = new Set(['active', 'retiring', 'revoked']);
const DAY_MS = 86_400_000;

export class AuthenticationError extends Error {
  constructor(message = 'A valid API key is required.', { code = 'UNAUTHENTICATED', details = {} } = {}) {
    super(message);
    this.name = 'AuthenticationError';
    this.code = code;
    this.details = details;
  }
}

export class AuthorizationError extends Error {
  constructor(message = 'The authenticated principal is not authorised for this operation.', details = {}) {
    super(message);
    this.name = 'AuthorizationError';
    this.code = 'FORBIDDEN';
    this.details = details;
  }
}

export function createAccessController({
  principals = loadPrincipalsFromEnvironment(),
  now = () => new Date(),
  allowLegacyPlaintext = process.env.NODE_ENV !== 'production',
  rotationWarningDays = normaliseInteger(process.env.WORKFORCE_AUDIT_CREDENTIAL_WARNING_DAYS ?? 14, 'rotationWarningDays', 1, 365)
} = {}) {
  const records = normalisePrincipals(principals, { allowLegacyPlaintext });

  function authenticate(req) {
    const suppliedKey = headerValue(req.headers['x-api-key']);
    if (!suppliedKey) throw new AuthenticationError();
    const record = resolveCredential(records, suppliedKey);
    if (!record) {
      throw new AuthenticationError(undefined, { details: { reason: 'invalid_key', keyId: credentialHint(suppliedKey) } });
    }

    const current = now();
    if (record.status === 'revoked') {
      throw new AuthenticationError('The API credential has been revoked.', { code: 'CREDENTIAL_REVOKED', details: { reason: 'revoked', keyId: record.keyId } });
    }
    if (record.notBefore && current < record.notBefore) {
      throw new AuthenticationError('The API credential is not active yet.', { code: 'CREDENTIAL_NOT_ACTIVE', details: { reason: 'not_before', keyId: record.keyId, notBefore: record.notBefore.toISOString() } });
    }
    if (record.expiresAt && current >= record.expiresAt) {
      throw new AuthenticationError('The API credential has expired.', { code: 'CREDENTIAL_EXPIRED', details: { reason: 'expired', keyId: record.keyId, expiresAt: record.expiresAt.toISOString() } });
    }

    const requestedTenant = headerValue(req.headers['x-tenant-id']);
    if (requestedTenant && requestedTenant !== record.tenantId) {
      throw new AuthorizationError('Tenant selection is controlled by the authenticated principal.', { reason: 'tenant_override', keyId: record.keyId, requestedTenant });
    }

    const expiresWithinWarning = record.expiresAt && record.expiresAt.getTime() - current.getTime() <= rotationWarningDays * DAY_MS;
    return Object.freeze({
      subject: record.subject,
      tenantId: record.tenantId,
      role: record.role,
      permissions: permissionsForRole(record.role),
      keyId: record.keyId,
      credentialStatus: record.status,
      credentialExpiresAt: record.expiresAt?.toISOString() ?? null,
      rotationRequired: record.status === 'retiring' || Boolean(expiresWithinWarning)
    });
  }

  function authorise(principal, permission) {
    if (!principal?.permissions?.includes(permission)) {
      throw new AuthorizationError(undefined, { reason: 'permission_denied', keyId: principal?.keyId ?? null, permission });
    }
    return principal;
  }

  function tenantIds() {
    return [...new Set(records.filter((record) => record.status !== 'revoked').map((record) => record.tenantId))];
  }

  function credentialHealth() {
    const current = now();
    const counts = { active: 0, retiring: 0, revoked: 0, expired: 0, notYetActive: 0, legacyPlaintext: 0, rotationRequired: 0 };
    let usable = 0;
    let nextExpiryAt = null;
    for (const record of records) {
      counts[record.status] += 1;
      if (record.mode === 'legacy') counts.legacyPlaintext += 1;
      if (record.notBefore && current < record.notBefore) counts.notYetActive += 1;
      else if (record.expiresAt && current >= record.expiresAt) counts.expired += 1;
      else if (record.status !== 'revoked') usable += 1;
      const rotationRequired = record.status === 'retiring'
        || Boolean(record.expiresAt && record.expiresAt.getTime() - current.getTime() <= rotationWarningDays * DAY_MS);
      if (rotationRequired && record.status !== 'revoked') counts.rotationRequired += 1;
      if (record.expiresAt && current < record.expiresAt && (!nextExpiryAt || record.expiresAt < nextExpiryAt)) nextExpiryAt = record.expiresAt;
    }
    return {
      status: usable > 0 ? 'ready' : 'unavailable',
      generatedAt: current.toISOString(),
      total: records.length,
      usable,
      rotationWarningDays,
      nextExpiryAt: nextExpiryAt?.toISOString() ?? null,
      ...counts
    };
  }

  return { authenticate, authorise, tenantIds, credentialHealth, principalCount: records.length };
}

export function permissionsForRole(role) {
  const permissions = ROLE_PERMISSIONS[role];
  if (!permissions) throw new TypeError(`Unsupported workforce-audit role: ${role}`);
  return [...permissions];
}

export function loadPrincipalsFromEnvironment(raw = process.env.WORKFORCE_AUDIT_API_KEYS) {
  if (!raw) {
    if (process.env.NODE_ENV === 'production') throw new Error('WORKFORCE_AUDIT_API_KEYS is required in production.');
    return [{ apiKey: 'local-development-key', subject: 'local-admin', tenantId: 'tenant-demo', role: 'compliance_admin' }];
  }
  try { return JSON.parse(raw); } catch { throw new Error('WORKFORCE_AUDIT_API_KEYS must be valid JSON.'); }
}

export function hashApiKeySecret(secret, salt) {
  const value = String(secret ?? '');
  const safeSalt = String(salt ?? '');
  if (value.length < 16) throw new TypeError('API key secrets must contain at least 16 characters.');
  if (safeSalt.length < 16) throw new TypeError('API key salts must contain at least 16 characters.');
  return scryptSync(value, safeSalt, 32).toString('base64');
}

export function credentialHint(value) {
  const supplied = String(value ?? '');
  const separator = supplied.indexOf('.');
  if (separator > 1) {
    const possibleId = supplied.slice(0, separator);
    if (/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(possibleId)) return possibleId;
  }
  return `legacy-${createHash('sha256').update(supplied).digest('hex').slice(0, 12)}`;
}

function normalisePrincipals(principals, { allowLegacyPlaintext }) {
  if (!Array.isArray(principals) || principals.length === 0) throw new TypeError('At least one workforce-audit principal is required.');
  if (principals.length > 100) throw new TypeError('No more than 100 local API-key principals are supported.');
  const identifiers = new Set();
  return principals.map((principal, index) => {
    if (!principal || typeof principal !== 'object' || Array.isArray(principal)) throw new TypeError(`Principal at index ${index} must be an object.`);
    const subject = cleanIdentifier(principal.subject, 'subject');
    const tenantId = cleanIdentifier(principal.tenantId, 'tenantId');
    const role = String(principal.role ?? '');
    permissionsForRole(role);
    const status = String(principal.status ?? 'active');
    if (!CREDENTIAL_STATUSES.has(status)) throw new TypeError(`Principal ${subject} has an unsupported credential status.`);
    const notBefore = optionalDate(principal.notBefore, 'notBefore');
    const expiresAt = optionalDate(principal.expiresAt, 'expiresAt');
    if (notBefore && expiresAt && expiresAt <= notBefore) throw new TypeError(`Principal ${subject} expiresAt must be after notBefore.`);

    let record;
    if (principal.apiKey !== undefined) {
      if (!allowLegacyPlaintext) throw new TypeError(`Principal ${subject} uses a plaintext apiKey, which is disabled in production.`);
      const apiKey = String(principal.apiKey);
      if (apiKey.length < 16) throw new TypeError(`Principal ${subject} has an API key shorter than 16 characters.`);
      record = {
        mode: 'legacy', apiKey,
        keyId: principal.keyId ? cleanIdentifier(principal.keyId, 'keyId') : credentialHint(apiKey),
        subject, tenantId, role, status, notBefore, expiresAt
      };
    } else {
      const keyId = cleanIdentifier(principal.keyId, 'keyId');
      const salt = String(principal.salt ?? '');
      const secretHash = String(principal.secretHash ?? '');
      if (salt.length < 16) throw new TypeError(`Principal ${subject} has an invalid credential salt.`);
      const decoded = Buffer.from(secretHash, 'base64');
      if (decoded.length !== 32 || decoded.toString('base64') !== secretHash) throw new TypeError(`Principal ${subject} has an invalid scrypt secretHash.`);
      record = { mode: 'scrypt', keyId, salt, secretHash, subject, tenantId, role, status, notBefore, expiresAt };
    }
    if (identifiers.has(record.keyId)) throw new TypeError('Duplicate workforce-audit credential key IDs are not allowed.');
    identifiers.add(record.keyId);
    return Object.freeze(record);
  });
}

function resolveCredential(records, suppliedKey) {
  const separator = suppliedKey.indexOf('.');
  if (separator > 1) {
    const keyId = suppliedKey.slice(0, separator);
    const secret = suppliedKey.slice(separator + 1);
    const record = records.find((candidate) => candidate.mode === 'scrypt' && candidate.keyId === keyId);
    if (record && verifyScrypt(record, secret)) return record;
  }
  return records.find((candidate) => candidate.mode === 'legacy' && safeEqual(candidate.apiKey, suppliedKey)) ?? null;
}

function verifyScrypt(record, secret) {
  try {
    const expected = Buffer.from(record.secretHash, 'base64');
    const actual = scryptSync(secret, record.salt, expected.length);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
  } catch { return false; }
}
function optionalDate(value, field) {
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError(`${field} must be a valid date.`);
  return date;
}
function normaliseInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}
function cleanIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}
function headerValue(value) { if (Array.isArray(value)) return value[0]?.trim(); return typeof value === 'string' ? value.trim() : ''; }
function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}
