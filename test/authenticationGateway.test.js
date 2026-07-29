import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createAuthenticationGateway } from '../src/security/authenticationGateway.js';

function apiController() {
  return {
    authenticate: () => ({ subject: 'api-user', tenantId: 'tenant-api', role: 'audit_viewer', permissions: ['audit:read'], keyId: 'api-1' }),
    tenantIds: () => ['tenant-api'],
    credentialHealth: () => ({ status: 'ready', total: 1, usable: 1 }),
    principalCount: 1
  };
}
function oidcAuthenticator({ signingKeyId = 'key-1' } = {}) {
  return {
    authenticateToken: async () => ({
      subject: 'oidc-user', externalSubjectHash: 'a'.repeat(24), tenantId: 'tenant-oidc',
      role: 'audit_manager', keyId: `oidc-${signingKeyId}-temporary`, signingKeyId,
      authMethod: 'oidc', credentialStatus: 'federated', credentialExpiresAt: null
    }),
    health: () => ({ status: 'ready', enabled: true, mode: 'oidc-jwks-bearer' })
  };
}

test('hybrid mode accepts exactly one API key or bearer token', async () => {
  const gateway = createAuthenticationGateway({ mode: 'hybrid', apiKeyController: apiController(), oidcAuthenticator: oidcAuthenticator(), oidcAllowedTenants: ['tenant-oidc'] });
  const api = await gateway.authenticate({ headers: { 'x-api-key': 'value' } });
  assert.equal(api.authMethod, 'api_key');
  const oidc = await gateway.authenticate({ headers: { authorization: 'Bearer a.b.c' } });
  assert.equal(oidc.authMethod, 'oidc');
  assert.equal(oidc.keyId, `oidc-${'a'.repeat(24)}`);
  assert.equal(oidc.permissions.includes('governance:read'), true);
  await assert.rejects(gateway.authenticate({ headers: { 'x-api-key': 'value', authorization: 'Bearer a.b.c' } }), (error) => error instanceof AuthenticationError && error.code === 'AMBIGUOUS_CREDENTIALS');
  assert.deepEqual(gateway.tenantIds().sort(), ['tenant-api', 'tenant-oidc']);
});

test('federated credential identity remains stable across signing-key rotation', async () => {
  const first = createAuthenticationGateway({ mode: 'oidc', oidcAuthenticator: oidcAuthenticator({ signingKeyId: 'key-1' }) });
  const second = createAuthenticationGateway({ mode: 'oidc', oidcAuthenticator: oidcAuthenticator({ signingKeyId: 'key-2' }) });
  const firstPrincipal = await first.authenticate({ headers: { authorization: 'Bearer first' } });
  const secondPrincipal = await second.authenticate({ headers: { authorization: 'Bearer second' } });
  assert.equal(firstPrincipal.keyId, secondPrincipal.keyId);
  assert.notEqual(firstPrincipal.signingKeyId, secondPrincipal.signingKeyId);
});

test('authentication modes reject disabled methods and tenant overrides', async () => {
  const apiOnly = createAuthenticationGateway({ mode: 'api-key', apiKeyController: apiController() });
  await assert.rejects(apiOnly.authenticate({ headers: { authorization: 'Bearer a.b.c' } }), (error) => error.code === 'AUTHENTICATION_METHOD_DISABLED');
  const oidcOnly = createAuthenticationGateway({ mode: 'oidc', oidcAuthenticator: oidcAuthenticator() });
  await assert.rejects(oidcOnly.authenticate({ headers: { 'x-api-key': 'value' } }), (error) => error.code === 'AUTHENTICATION_METHOD_DISABLED');
  await assert.rejects(oidcOnly.authenticate({ headers: { authorization: 'Bearer a.b.c', 'x-tenant-id': 'tenant-other' } }), (error) => error instanceof AuthorizationError && error.details.reason === 'tenant_override');
});

test('gateway health requires every enabled authentication method', () => {
  const gateway = createAuthenticationGateway({
    mode: 'hybrid',
    apiKeyController: apiController(),
    oidcAuthenticator: { ...oidcAuthenticator(), health: () => ({ status: 'unavailable', enabled: true }) }
  });
  const health = gateway.credentialHealth();
  assert.equal(health.status, 'unavailable');
  assert.equal(health.authenticationMode, 'hybrid');
});
