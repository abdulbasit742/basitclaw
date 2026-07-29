import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateScimCredential,
  parseScimCredentialArguments
} from '../scripts/generate-scim-credential.js';

test('SCIM credential CLI accepts named expiry and scope options', () => {
  const input = parseScimCredentialArguments([
    'scim.key-2026', 'enterprise-idp',
    '--scopes', 'scim:read',
    '--expires-at', '2026-10-31T00:00:00Z'
  ]);
  assert.deepEqual(input, {
    keyId: 'scim.key-2026',
    subject: 'enterprise-idp',
    expiresAt: '2026-10-31T00:00:00Z',
    scopes: 'scim:read'
  });
  const generated = generateScimCredential(input);
  assert.match(generated.presentedToken, /^scim\.key-2026\./);
  assert.deepEqual(generated.record.scopes, ['scim:read']);
  assert.equal(generated.record.expiresAt, '2026-10-31T00:00:00.000Z');
  assert.equal('presentedToken' in generated.record, false);
});

test('SCIM credential CLI rejects duplicate and unsupported options', () => {
  assert.throws(
    () => parseScimCredentialArguments(['scim-1', 'idp', '2026-10-31T00:00:00Z', '--expires-at', '2026-11-01T00:00:00Z']),
    /either positionally/
  );
  assert.throws(
    () => parseScimCredentialArguments(['scim-1', 'idp', '--unknown', 'value']),
    /Unsupported option/
  );
});
