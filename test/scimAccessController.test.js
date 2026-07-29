import test from 'node:test';
import assert from 'node:assert/strict';
import { scryptSync } from 'node:crypto';
import {
  createScimAccessController,
  ScimAuthenticationError,
  ScimAuthorizationError
} from '../src/security/scimAccessController.js';

const salt = '0123456789abcdef0123456789abcdef';
const secret = '0123456789abcdef0123456789abcdef';
const secretHash = scryptSync(secret, salt, 32).toString('base64');

function record(overrides = {}) {
  return {
    keyId: 'scim.key-1', subject: 'enterprise-idp', salt, secretHash,
    scopes: ['scim:read', 'scim:write'], status: 'active', ...overrides
  };
}
function request(token = `scim.key-1.${secret}`) {
  return { headers: { authorization: `Bearer ${token}` } };
}

test('SCIM credentials support dotted key IDs and asynchronous verification', async () => {
  const controller = createScimAccessController({ credentials: [record()] });
  const principal = await controller.authenticate(request());
  assert.equal(principal.keyId, 'scim.key-1');
  assert.deepEqual(principal.scopes, ['scim:read', 'scim:write']);
});

test('SCIM credentials require explicit fail-closed scopes', () => {
  assert.throws(
    () => createScimAccessController({ credentials: [record({ scopes: undefined })] }),
    /explicit scopes array/
  );
  assert.throws(
    () => createScimAccessController({ credentials: [record({ scopes: ['scim:admin'] })] }),
    /invalid scopes/
  );
});

test('read-only SCIM credentials cannot perform writes', async () => {
  const controller = createScimAccessController({ credentials: [record({ scopes: ['scim:read'] })] });
  const principal = await controller.authenticate(request());
  assert.throws(() => controller.authorise(principal, 'scim:write'), ScimAuthorizationError);
});

test('revoked, expired, and not-yet-active credentials return specific lifecycle codes', async () => {
  const current = () => new Date('2026-07-29T00:00:00Z');
  for (const [overrides, code] of [
    [{ status: 'revoked' }, 'SCIM_CREDENTIAL_REVOKED'],
    [{ expiresAt: '2026-07-28T00:00:00Z' }, 'SCIM_CREDENTIAL_EXPIRED'],
    [{ notBefore: '2026-07-30T00:00:00Z' }, 'SCIM_CREDENTIAL_NOT_ACTIVE']
  ]) {
    const controller = createScimAccessController({ credentials: [record(overrides)], now: current });
    await assert.rejects(
      controller.authenticate(request()),
      (error) => error instanceof ScimAuthenticationError && error.code === code
    );
    assert.equal(controller.health().status, 'unavailable');
  }
});
