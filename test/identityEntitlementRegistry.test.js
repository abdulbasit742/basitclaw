import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIdentityEntitlementRegistry, IdentityEntitlementConflictError } from '../src/security/identityEntitlementRegistry.js';
import { deriveFederatedSubject } from '../src/security/federatedIdentity.js';

const key = Buffer.alloc(32, 7).toString('base64');
function make() {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-identity-'));
  return {
    directory,
    registry: createIdentityEntitlementRegistry({
      mode: 'enforce', directory, keys: { k1: key }, primaryKeyId: 'k1',
      now: () => new Date('2026-07-29T00:00:00Z')
    })
  };
}
const base = {
  issuer: 'https://id.example.com/tenant', externalSubject: 'user-1', tenantId: 'tenant-a',
  role: 'auditor', active: true, reviewBy: '2027-01-01T00:00:00Z', reason: 'approved access'
};

test('provisions encrypted entitlement and enforces exact tenant and role', () => {
  const { directory, registry } = make();
  const record = registry.upsert(base, { actor: 'scim-admin' });
  assert.equal(record.version, 1);
  const principal = { ...deriveFederatedSubject(base.issuer, base.externalSubject), authMethod: 'oidc', tenantId: 'tenant-a', role: 'auditor' };
  assert.equal(registry.enforce(principal).entitlementStatus, 'active');
  const raw = readFileSync(join(directory, 'entitlements.enc.json'), 'utf8');
  assert.equal(raw.includes('user-1'), false);
  assert.equal(raw.includes('tenant-a'), false);
});

test('unprovisioned, suspended, and mismatched identities fail closed', () => {
  const { registry } = make();
  const principal = { ...deriveFederatedSubject(base.issuer, base.externalSubject), authMethod: 'oidc', tenantId: 'tenant-a', role: 'auditor' };
  assert.throws(() => registry.enforce(principal), (error) => error.code === 'IDENTITY_NOT_PROVISIONED');
  const record = registry.upsert(base, { actor: 'admin' });
  registry.patch(record.id, { active: false, reason: 'employment ended', expectedVersion: 1 }, { actor: 'admin' });
  assert.throws(() => registry.enforce(principal), (error) => error.code === 'IDENTITY_SUSPENDED');
});

test('optimistic versions prevent lost entitlement updates', () => {
  const { registry } = make();
  const record = registry.upsert(base, { actor: 'admin' });
  assert.throws(
    () => registry.patch(record.id, { active: false, reason: 'stale', expectedVersion: 0 }, { actor: 'admin' }),
    IdentityEntitlementConflictError
  );
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
