import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import {
  OidcAuthenticationError,
  createOidcAuthenticator,
  createOidcAuthenticatorFromEnvironment
} from '../src/security/oidcAuthenticator.js';

const issuer = 'https://id.example.com';
const audience = 'workforce-audit';
const nowSeconds = Math.floor(new Date('2026-07-29T16:00:00.000Z').getTime() / 1000);
const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = keys.publicKey.export({ format: 'jwk' });
publicJwk.kid = 'key-1';
publicJwk.use = 'sig';
publicJwk.alg = 'RS256';

function token(overrides = {}, headerOverrides = {}, signingKey = keys.privateKey) {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'key-1', ...headerOverrides };
  const payload = {
    iss: issuer,
    aud: audience,
    sub: 'user-123',
    iat: nowSeconds - 60,
    exp: nowSeconds + 600,
    tenant_id: 'tenant-acme',
    groups: ['audit-managers'],
    acr: 'urn:mfa',
    amr: ['pwd', 'mfa'],
    jti: 'token-123',
    ...overrides
  };
  const first = Buffer.from(JSON.stringify(header)).toString('base64url');
  const second = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = sign('RSA-SHA256', Buffer.from(`${first}.${second}`), signingKey).toString('base64url');
  return `${first}.${second}.${signature}`;
}

function authenticator(options = {}) {
  return createOidcAuthenticator({
    issuer,
    audience,
    staticJwks: { keys: [publicJwk] },
    groupRoleMap: { 'audit-managers': 'audit_manager', viewers: 'audit_viewer' },
    allowedTenants: ['tenant-acme'],
    requiredAcr: ['urn:mfa'],
    requiredAmr: ['mfa'],
    now: () => new Date(nowSeconds * 1000),
    ...options
  });
}

test('validates a signed token and maps tenant, group, and assurance claims', async () => {
  const principal = await authenticator().authenticateToken(token());
  assert.equal(principal.authMethod, 'oidc');
  assert.equal(principal.tenantId, 'tenant-acme');
  assert.equal(principal.role, 'audit_manager');
  assert.match(principal.keyId, /^oidc-key-1-[a-f0-9]{12}$/);
  assert.equal(principal.signingKeyId, 'key-1');
  assert.equal(principal.credentialExpiresAt, new Date((nowSeconds + 600) * 1000).toISOString());
  assert.equal(principal.authenticationContext.acr, 'urn:mfa');
  assert.deepEqual(principal.authenticationContext.amr, ['pwd', 'mfa']);
  assert.match(principal.subject, /^oidc-[a-f0-9]{24}$/);
});

test('rejects issuer, audience, expiry, excessive lifetime, tenant, and MFA failures', async () => {
  const cases = [
    [token({ iss: 'https://evil.example.com' }), 'OIDC_ISSUER_INVALID'],
    [token({ aud: 'another-api' }), 'OIDC_AUDIENCE_INVALID'],
    [token({ exp: nowSeconds - 120 }), 'OIDC_TOKEN_EXPIRED'],
    [token({ iat: nowSeconds - 7200, exp: nowSeconds + 60 }), 'OIDC_TOKEN_LIFETIME_INVALID'],
    [token({ tenant_id: 'tenant-other' }), 'OIDC_TENANT_NOT_ALLOWED'],
    [token({ amr: ['pwd'] }), 'OIDC_AMR_REQUIRED'],
    [token({ acr: 'urn:pwd' }), 'OIDC_ACR_REQUIRED']
  ];
  for (const [value, code] of cases) {
    await assert.rejects(authenticator().authenticateToken(value), (error) => error instanceof OidcAuthenticationError && error.code === code);
  }
});

test('rejects ambiguous or missing role mappings', async () => {
  await assert.rejects(authenticator().authenticateToken(token({ groups: ['unknown'] })), (error) => error.code === 'OIDC_ROLE_NOT_MAPPED');
  await assert.rejects(authenticator().authenticateToken(token({ groups: ['audit-managers', 'viewers'] })), (error) => error.code === 'OIDC_ROLE_AMBIGUOUS');
});

test('rejects unknown keys, forbidden algorithms, malformed tokens, and bad signatures', async () => {
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  await assert.rejects(authenticator().authenticateToken(token({}, { kid: 'missing' })), (error) => error.code === 'OIDC_SIGNING_KEY_UNKNOWN');
  await assert.rejects(authenticator().authenticateToken(token({}, { alg: 'HS256' })), (error) => error.code === 'OIDC_ALGORITHM_NOT_ALLOWED');
  await assert.rejects(authenticator().authenticateToken('not-a-jwt'), (error) => error.code === 'OIDC_TOKEN_MALFORMED');
  await assert.rejects(authenticator().authenticateToken(token({}, {}, other.privateKey)), (error) => error.code === 'OIDC_SIGNATURE_INVALID');
});

test('rejects oversized tokens, header key references, and weak RSA keys', async () => {
  await assert.rejects(authenticator().authenticateToken('a'.repeat(16_385)), (error) => error.code === 'OIDC_TOKEN_MALFORMED');
  await assert.rejects(authenticator().authenticateToken(token({}, { jku: 'https://evil.example/jwks' })), (error) => error.code === 'OIDC_HEADER_KEY_REFERENCE_FORBIDDEN');
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
  const weakJwk = weak.publicKey.export({ format: 'jwk' });
  Object.assign(weakJwk, { kid: 'weak-key', use: 'sig', alg: 'RS256' });
  const weakAuthenticator = createOidcAuthenticator({
    issuer,
    audience,
    staticJwks: { keys: [weakJwk] },
    groupRoleMap: { 'audit-managers': 'audit_manager' },
    allowedTenants: ['tenant-acme'],
    now: () => new Date(nowSeconds * 1000)
  });
  await assert.rejects(weakAuthenticator.authenticateToken(token({}, { kid: 'weak-key' }, weak.privateKey)), (error) => error.code === 'OIDC_SIGNING_KEY_INVALID');
});

test('refreshes JWKS once for an unknown key and honours cache headers', async () => {
  const rotated = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rotatedJwk = rotated.publicKey.export({ format: 'jwk' });
  Object.assign(rotatedJwk, { kid: 'key-2', use: 'sig', alg: 'RS256' });
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'public, max-age=120' },
      text: async () => JSON.stringify({ keys: calls === 1 ? [publicJwk] : [publicJwk, rotatedJwk] })
    };
  };
  const instance = createOidcAuthenticator({
    issuer,
    audience,
    jwksUri: 'https://id.example.com/.well-known/jwks.json',
    groupRoleMap: { 'audit-managers': 'audit_manager' },
    fetchImpl,
    now: () => new Date(nowSeconds * 1000)
  });
  const rotatedToken = token({}, { kid: 'key-2' }, rotated.privateKey);
  const principal = await instance.authenticateToken(rotatedToken);
  assert.match(principal.keyId, /^oidc-key-2-[a-f0-9]{12}$/);
  assert.equal(calls, 2);
  assert.equal(instance.health().cacheState, 'fresh');
});

test('supports safe nested tenant and group claim paths', async () => {
  const instance = createOidcAuthenticator({
    issuer,
    audience,
    staticJwks: { keys: [publicJwk] },
    groupRoleMap: { 'audit-managers': 'audit_manager' },
    tenantClaim: 'organisation.tenant',
    groupsClaim: 'realm.groups',
    allowedTenants: ['tenant-acme'],
    now: () => new Date(nowSeconds * 1000)
  });
  const principal = await instance.authenticateToken(token({
    tenant_id: undefined,
    groups: undefined,
    organisation: { tenant: 'tenant-acme' },
    realm: { groups: ['audit-managers'] }
  }));
  assert.equal(principal.tenantId, 'tenant-acme');
  assert.equal(principal.role, 'audit_manager');
});

test('production OIDC requires an explicit tenant boundary', () => {
  assert.throws(() => createOidcAuthenticatorFromEnvironment({
    NODE_ENV: 'production',
    WORKFORCE_AUDIT_OIDC_ISSUER: issuer,
    WORKFORCE_AUDIT_OIDC_AUDIENCE: audience,
    WORKFORCE_AUDIT_OIDC_STATIC_JWKS: JSON.stringify({ keys: [publicJwk] }),
    WORKFORCE_AUDIT_OIDC_GROUP_ROLE_MAP: JSON.stringify({ 'audit-managers': 'audit_manager' })
  }), /OIDC_ALLOWED_TENANTS is required/);
});
