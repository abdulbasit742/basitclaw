import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityAlertCodec } from '../src/security/securityAlertCodec.js';

const oldSecret = 'old-security-alert-signing-secret-1234567890';
const newSecret = 'new-security-alert-signing-secret-1234567890';
const body = JSON.stringify({ version: 1, deliveryId: 'ALERT-test' });
const timestamp = new Date('2026-07-29T00:00:00.000Z');

test('webhook signing keyring emits the primary key ID and verifies overlap keys', () => {
  const oldCodec = createSecurityAlertCodec({
    signingSecrets: { 'old-key': oldSecret },
    primarySigningKeyId: 'old-key'
  });
  const keyring = createSecurityAlertCodec({
    signingSecrets: { 'old-key': oldSecret, 'new-key': newSecret },
    primarySigningKeyId: 'new-key'
  });

  const newHeaders = keyring.headers(body, 'ALERT-1', timestamp);
  assert.equal(newHeaders['x-basitclaw-key-id'], 'new-key');
  assert.equal(keyring.verify(
    body,
    newHeaders['x-basitclaw-timestamp'],
    newHeaders['x-basitclaw-signature'],
    'new-key'
  ), true);

  const oldHeaders = oldCodec.headers(body, 'ALERT-1', timestamp);
  assert.equal(keyring.verify(
    body,
    oldHeaders['x-basitclaw-timestamp'],
    oldHeaders['x-basitclaw-signature'],
    'old-key'
  ), true);
  assert.equal(keyring.verify(
    `${body}tampered`,
    oldHeaders['x-basitclaw-timestamp'],
    oldHeaders['x-basitclaw-signature'],
    'old-key'
  ), false);
});

test('unknown webhook signing key IDs fail verification closed', () => {
  const keyring = createSecurityAlertCodec({
    signingSecrets: { 'new-key': newSecret },
    primarySigningKeyId: 'new-key'
  });
  const headers = keyring.headers(body, 'ALERT-1', timestamp);
  assert.equal(keyring.verify(body, headers['x-basitclaw-timestamp'], headers['x-basitclaw-signature'], 'missing-key'), false);
});
