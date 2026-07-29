import test from 'node:test';
import assert from 'node:assert/strict';
import { createAuthenticationGateway } from '../src/security/authenticationGateway.js';
import { IdentityEntitlementError } from '../src/security/identityEntitlementRegistry.js';

function apiController() {
  return {
    authenticate: () => ({ subject: 'api-user', tenantId: 'tenant-a', role: 'auditor', permissions: ['audit:read'], keyId: 'api-1' }),
    tenantIds: () => ['tenant-a'],
    credentialHealth: () => ({ status: 'ready', total: 1, usable: 1 }),
    principalCount: 1
  };
}

function oidcPrincipal() {
  return {
    subject: 'oidc-1234567890abcdef12345678',
    externalSubjectHash: '1234567890abcdef12345678',
    tenantId: 'tenant-a',
    role: 'auditor',
    authMethod: 'oidc',
    signingKeyId: 'signing-1',
    credentialStatus: 'federated',
    credentialExpiresAt: '2026-07-29T23:00:00.000Z',
    rotationRequired: false
  };
}

test('authentication gateway enforces provisioned federated entitlements', async () => {
  const entitlementRegistry = {
    enforce(principal) {
      return { ...principal, entitlementStatus: 'active', entitlementId: 'IDN-1', entitlementVersion: 3 };
    },
    tenantIds: () => ['tenant-a'],
    health: () => ({ status: 'ready', enabled: true, required: true, mode: 'enforce', total: 1 })
  };
  const gateway = createAuthenticationGateway({
    mode: 'hybrid',
    apiKeyController: apiController(),
    oidcAuthenticator: { authenticateToken: async () => oidcPrincipal(), health: () => ({ status: 'ready' }) },
    oidcAllowedTenants: ['tenant-a'],
    entitlementRegistry
  });
  const principal = await gateway.authenticate({ headers: { authorization: 'Bearer token' } });
  assert.equal(principal.entitlementStatus, 'active');
  assert.equal(principal.entitlementVersion, 3);
  assert.equal(principal.keyId, 'oidc-1234567890abcdef12345678');
  assert.ok(principal.permissions.includes('finding:write'));
  assert.deepEqual(gateway.tenantIds(), ['tenant-a']);
  assert.equal(gateway.credentialHealth().identityEntitlements.status, 'ready');
});

test('entitlement suspension propagates and required health fails closed', async () => {
  const entitlementRegistry = {
    enforce(principal) {
      throw new IdentityEntitlementError('Suspended.', 'IDENTITY_SUSPENDED', { subject: principal.subject });
    },
    tenantIds: () => [],
    health: () => ({ status: 'unavailable', enabled: true, required: true, mode: 'enforce' })
  };
  const gateway = createAuthenticationGateway({
    mode: 'oidc',
    oidcAuthenticator: { authenticateToken: async () => oidcPrincipal(), health: () => ({ status: 'ready' }) },
    entitlementRegistry
  });
  await assert.rejects(
    gateway.authenticate({ headers: { authorization: 'Bearer token' } }),
    (error) => error.code === 'IDENTITY_SUSPENDED'
  );
  assert.equal(gateway.credentialHealth().status, 'unavailable');
});
