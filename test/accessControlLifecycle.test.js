import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthenticationError,
  createAccessController,
  hashApiKeySecret
} from '../src/security/accessControl.js';
import { generateApiCredential } from '../scripts/generate-api-credential.js';

const salt = 'credential-salt-123456';
const secret = 'credential-secret-123456789';
const base = {
  keyId: 'ops-2026-q3',
  salt,
  secretHash: hashApiKeySecret(secret, salt),
  subject: 'security.admin',
  tenantId: 'tenant-a',
  role: 'compliance_admin'
};
const req = (key, extra = {}) => ({ headers: { 'x-api-key': key, ...extra } });

test('scrypt credential authenticates keyId.secret and exposes rotation metadata', () => {
  const access = createAccessController({
    principals: [{ ...base, status: 'retiring', expiresAt: '2026-08-05T00:00:00Z' }],
    now: () => new Date('2026-07-29T00:00:00Z'),
    allowLegacyPlaintext: false
  });
  const principal = access.authenticate(req(`${base.keyId}.${secret}`));
  assert.equal(principal.keyId, base.keyId);
  assert.equal(principal.rotationRequired, true);
  assert.ok(principal.permissions.includes('security:read'));
});

test('wrong, revoked, expired, and not-yet-active credentials fail closed', () => {
  const now = () => new Date('2026-07-29T00:00:00Z');
  const invalid = createAccessController({ principals: [base], now, allowLegacyPlaintext: false });
  assert.throws(() => invalid.authenticate(req(`${base.keyId}.wrong-secret-123456789`)), AuthenticationError);

  const revoked = createAccessController({ principals: [{ ...base, status: 'revoked' }], now, allowLegacyPlaintext: false });
  assert.throws(() => revoked.authenticate(req(`${base.keyId}.${secret}`)), (error) => error.code === 'CREDENTIAL_REVOKED');

  const expired = createAccessController({ principals: [{ ...base, expiresAt: '2026-07-28T00:00:00Z' }], now, allowLegacyPlaintext: false });
  assert.throws(() => expired.authenticate(req(`${base.keyId}.${secret}`)), (error) => error.code === 'CREDENTIAL_EXPIRED');

  const future = createAccessController({ principals: [{ ...base, notBefore: '2026-07-30T00:00:00Z' }], now, allowLegacyPlaintext: false });
  assert.throws(() => future.authenticate(req(`${base.keyId}.${secret}`)), (error) => error.code === 'CREDENTIAL_NOT_ACTIVE');
});

test('production hardening rejects plaintext keys and health reports usable credentials', () => {
  assert.throws(() => createAccessController({
    principals: [{ apiKey: 'legacy-key-123456789', subject: 'legacy.user', tenantId: 'tenant-a', role: 'audit_viewer' }],
    allowLegacyPlaintext: false
  }), /plaintext apiKey/);

  const access = createAccessController({
    principals: [base, { ...base, keyId: 'revoked-key', status: 'revoked' }],
    now: () => new Date('2026-07-29T00:00:00Z'),
    allowLegacyPlaintext: false
  });
  const health = access.credentialHealth();
  assert.equal(health.total, 2);
  assert.equal(health.usable, 1);
  assert.equal(health.revoked, 1);
  assert.equal(health.status, 'ready');
});

test('credential generator emits a one-time presented key that authenticates against its record', () => {
  const generated = generateApiCredential({
    keyId: 'generated-q3',
    subject: 'generated.admin',
    tenantId: 'tenant-a',
    role: 'compliance_admin',
    expiresAt: '2026-10-31T00:00:00Z'
  });
  assert.match(generated.presentedKey, /^generated-q3\./);
  assert.equal(Object.hasOwn(generated.record, 'apiKey'), false);
  const access = createAccessController({
    principals: [generated.record],
    now: () => new Date('2026-07-29T00:00:00Z'),
    allowLegacyPlaintext: false
  });
  assert.equal(access.authenticate(req(generated.presentedKey)).subject, 'generated.admin');
});
