import { timingSafeEqual } from 'node:crypto';

const ROLE_PERMISSIONS = Object.freeze({
  audit_viewer: ['audit:read'],
  auditor: ['audit:read', 'fieldwork:write', 'finding:write'],
  audit_manager: [
    'audit:read', 'engagement:write', 'fieldwork:write', 'finding:write', 'governance:read',
    'backup:read', 'backup:write', 'replica:read', 'replica:write', 'resilience:read', 'drill:run'
  ],
  compliance_admin: [
    'audit:read', 'engagement:write', 'fieldwork:write', 'finding:write', 'governance:read',
    'backup:read', 'backup:write', 'backup:restore', 'replica:read', 'replica:write',
    'resilience:read', 'resilience:run', 'drill:run'
  ]
});

export class AuthenticationError extends Error {
  constructor(message = 'A valid API key is required.') {
    super(message);
    this.name = 'AuthenticationError';
    this.code = 'UNAUTHENTICATED';
  }
}

export class AuthorizationError extends Error {
  constructor(message = 'The authenticated principal is not authorised for this operation.') {
    super(message);
    this.name = 'AuthorizationError';
    this.code = 'FORBIDDEN';
  }
}

export function createAccessController({ principals = loadPrincipalsFromEnvironment() } = {}) {
  const records = normalisePrincipals(principals);

  function authenticate(req) {
    const suppliedKey = headerValue(req.headers['x-api-key']);
    if (!suppliedKey) throw new AuthenticationError();
    const record = records.find((candidate) => safeEqual(candidate.apiKey, suppliedKey));
    if (!record) throw new AuthenticationError();
    const requestedTenant = headerValue(req.headers['x-tenant-id']);
    if (requestedTenant && requestedTenant !== record.tenantId) {
      throw new AuthorizationError('Tenant selection is controlled by the authenticated principal.');
    }
    return Object.freeze({
      subject: record.subject,
      tenantId: record.tenantId,
      role: record.role,
      permissions: permissionsForRole(record.role)
    });
  }

  function authorise(principal, permission) {
    if (!principal?.permissions?.includes(permission)) throw new AuthorizationError();
    return principal;
  }

  function tenantIds() {
    return [...new Set(records.map((record) => record.tenantId))];
  }

  return { authenticate, authorise, tenantIds, principalCount: records.length };
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
  let parsed;
  try { parsed = JSON.parse(raw); } catch { throw new Error('WORKFORCE_AUDIT_API_KEYS must be valid JSON.'); }
  return parsed;
}

function normalisePrincipals(principals) {
  if (!Array.isArray(principals) || principals.length === 0) throw new TypeError('At least one workforce-audit principal is required.');
  if (principals.length > 100) throw new TypeError('No more than 100 local API-key principals are supported.');
  const keys = new Set();
  return principals.map((principal, index) => {
    if (!principal || typeof principal !== 'object') throw new TypeError(`Principal at index ${index} must be an object.`);
    const apiKey = String(principal.apiKey ?? '');
    const subject = cleanIdentifier(principal.subject, 'subject');
    const tenantId = cleanIdentifier(principal.tenantId, 'tenantId');
    const role = String(principal.role ?? '');
    permissionsForRole(role);
    if (apiKey.length < 16) throw new TypeError(`Principal ${subject} has an API key shorter than 16 characters.`);
    if (keys.has(apiKey)) throw new TypeError('Duplicate workforce-audit API keys are not allowed.');
    keys.add(apiKey);
    return Object.freeze({ apiKey, subject, tenantId, role });
  });
}

function cleanIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}

function headerValue(value) {
  if (Array.isArray(value)) return value[0]?.trim();
  return typeof value === 'string' ? value.trim() : '';
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}
