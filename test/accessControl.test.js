import test from 'node:test';
import assert from 'node:assert/strict';
import { AuthenticationError, AuthorizationError, createAccessController, permissionsForRole } from '../src/security/accessControl.js';

const principals = [
  { apiKey: 'viewer-key-1234567890', subject: 'viewer.one', tenantId: 'tenant-a', role: 'audit_viewer' },
  { apiKey: 'manager-key-123456789', subject: 'manager.one', tenantId: 'tenant-a', role: 'audit_manager' }
];

test('authentication resolves a fixed tenant and role', () => {
  const access = createAccessController({ principals });
  const principal = access.authenticate({ headers: { 'x-api-key': 'viewer-key-1234567890' } });
  assert.equal(principal.tenantId, 'tenant-a');
  assert.equal(principal.role, 'audit_viewer');
  assert.deepEqual(principal.permissions, ['audit:read']);
});

test('invalid API keys and tenant overrides are rejected', () => {
  const access = createAccessController({ principals });
  assert.throws(() => access.authenticate({ headers: { 'x-api-key': 'wrong-key-1234567890' } }), AuthenticationError);
  assert.throws(() => access.authenticate({ headers: { 'x-api-key': principals[0].apiKey, 'x-tenant-id': 'tenant-b' } }), AuthorizationError);
});

test('role permissions enforce engagement planning boundaries', () => {
  const access = createAccessController({ principals });
  const viewer = access.authenticate({ headers: { 'x-api-key': principals[0].apiKey } });
  assert.throws(() => access.authorise(viewer, 'engagement:write'), AuthorizationError);
  assert.ok(permissionsForRole('audit_manager').includes('governance:read'));
});
