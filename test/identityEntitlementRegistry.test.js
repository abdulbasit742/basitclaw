import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createDisabledIdentityEntitlementRegistry,
  createIdentityEntitlementRegistry,
  IdentityEntitlementConflictError
} from '../src/security/identityEntitlementRegistry.js';
import { deriveFederatedSubject } from '../src/security/federatedIdentity.js';

const key = Buffer.alloc(32, 7).toString('base64');
function make(mode = 'enforce') {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-identity-'));
  let current = new Date('2026-07-29T00:00:00Z');
  return {
    directory,
    setNow(value) { current = new Date(value); },
    registry: createIdentityEntitlementRegistry({
      mode, directory, keys: { k1: key }, primaryKeyId: 'k1',
      now: () => new Date(current)
    })
  };
}
const base = {
  issuer: 'https://id.example.com/tenant', externalSubject: 'user-1', tenantId: 'tenant-a',
  role: 'auditor', active: true, reviewBy: '2027-01-01T00:00:00Z', reason: 'approved access'
};
function principal(overrides = {}) {
  return {
    ...deriveFederatedSubject(base.issuer, base.externalSubject),
    authMethod: 'oidc', tenantId: 'tenant-a', role: 'auditor', ...overrides
  };
}

test('provisions encrypted entitlement and enforces exact tenant and role', () => {
  const { directory, registry } = make();
  const record = registry.upsert(base, { actor: 'scim-admin' });
  assert.equal(record.version, 1);
  assert.equal(registry.enforce(principal()).entitlementStatus, 'active');
  const raw = readFileSync(join(directory, 'entitlements.enc.json'), 'utf8');
  assert.equal(raw.includes('user-1'), false);
  assert.equal(raw.includes('tenant-a'), false);
});

test('unprovisioned, mismatched, and suspended identities fail closed', () => {
  const { registry } = make();
  assert.throws(() => registry.enforce(principal()), (error) => error.code === 'IDENTITY_NOT_PROVISIONED');
  const record = registry.upsert(base, { actor: 'admin' });
  assert.throws(
    () => registry.enforce(principal({ tenantId: 'tenant-b' })),
    (error) => error.code === 'IDENTITY_ENTITLEMENT_MISMATCH'
  );
  assert.throws(
    () => registry.enforce(principal({ role: 'audit_manager' })),
    (error) => error.code === 'IDENTITY_ENTITLEMENT_MISMATCH'
  );
  registry.patch(record.id, { active: false, reason: 'employment ended', expectedVersion: 1 }, { actor: 'admin' });
  assert.throws(() => registry.enforce(principal()), (error) => error.code === 'IDENTITY_SUSPENDED');
});

test('observe mode reports every entitlement issue without denying the principal', () => {
  const { registry, setNow } = make('observe');
  assert.equal(registry.enforce(principal()).entitlementStatus, 'unprovisioned');
  const record = registry.upsert({ ...base, reviewBy: '2026-08-01T00:00:00Z' }, { actor: 'admin' });
  assert.equal(registry.enforce(principal({ tenantId: 'tenant-b' })).entitlementStatus, 'mismatched');
  registry.patch(record.id, { active: false, reason: 'observe suspension', expectedVersion: 1 }, { actor: 'admin' });
  assert.equal(registry.enforce(principal()).entitlementStatus, 'suspended');
  registry.patch(record.id, { active: true, reason: 'observe reactivation', expectedVersion: 2 }, { actor: 'admin' });
  setNow('2026-08-02T00:00:00Z');
  assert.equal(registry.enforce(principal()).entitlementStatus, 'review_overdue');
  const health = registry.health();
  assert.equal(health.status, 'ready');
  assert.equal(health.reviewStatus, 'attention');
});

test('optimistic versions prevent lost entitlement updates', () => {
  const { registry } = make();
  const record = registry.upsert(base, { actor: 'admin' });
  assert.throws(
    () => registry.patch(record.id, { active: false, reason: 'stale', expectedVersion: 0 }, { actor: 'admin' }),
    IdentityEntitlementConflictError
  );
});

test('disabled lifecycle exposes a complete fail-closed management API', () => {
  const registry = createDisabledIdentityEntitlementRegistry();
  assert.equal(registry.enforce(principal()).subject, principal().subject);
  assert.throws(() => registry.upsert(base), (error) => error.code === 'IDENTITY_ENTITLEMENT_LIFECYCLE_DISABLED');
  assert.throws(() => registry.get('IDN-1'), (error) => error.code === 'IDENTITY_ENTITLEMENT_LIFECYCLE_DISABLED');
  assert.equal(registry.getBySubject('unknown'), null);
});

test('encrypted entitlement tampering fails health closed', () => {
  const { directory, registry } = make();
  registry.upsert(base, { actor: 'admin' });
  const path = join(directory, 'entitlements.enc.json');
  const value = JSON.parse(readFileSync(path, 'utf8'));
  value.ciphertext = `${value.ciphertext.slice(0, -4)}AAAA`;
  writeFileSync(path, JSON.stringify(value));
  assert.equal(registry.health().status, 'unavailable');
});
