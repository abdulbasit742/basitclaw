import test from 'node:test';
import assert from 'node:assert/strict';
import { runSecurityKeyCommand } from '../scripts/security-keys.js';

const disabled = {
  WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE: 'disabled',
  WORKFORCE_AUDIT_SECURITY_ALERT_MODE: 'disabled'
};

test('security key CLI reports disabled controls without exposing secrets', () => {
  const result = runSecurityKeyCommand(['status'], disabled);
  assert.equal(result.archive.status, 'disabled');
  assert.equal(result.alertSigning.status, 'disabled');
  assert.doesNotMatch(JSON.stringify(result), /secret|base64-32-byte-key/i);
});

test('security key CLI refuses retirement checks for disabled controls', () => {
  const archive = runSecurityKeyCommand(['archive-can-retire', 'old-key'], disabled);
  const alert = runSecurityKeyCommand(['alert-can-retire', 'old-key'], disabled);
  assert.equal(archive.safe, false);
  assert.equal(archive.reason, 'control_disabled');
  assert.equal(alert.safe, false);
  assert.equal(alert.reason, 'control_disabled');
});

test('alert signing retirement requires explicit receiver confirmation', () => {
  const env = {
    WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE: 'disabled',
    WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS: JSON.stringify({
      'old-key': 'old-security-alert-signing-secret-1234567890',
      'new-key': 'new-security-alert-signing-secret-1234567890'
    }),
    WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID: 'new-key'
  };
  const unconfirmed = runSecurityKeyCommand(['alert-can-retire', 'old-key'], env);
  const confirmed = runSecurityKeyCommand(['alert-can-retire', 'old-key', '--receiver-confirmed'], env);
  assert.equal(unconfirmed.safe, false);
  assert.equal(unconfirmed.reason, 'receiver_overlap_confirmation_required');
  assert.equal(confirmed.safe, true);
  assert.equal(confirmed.reason, 'receiver_overlap_confirmed');
});

test('security key CLI rejects unknown commands and confirmation flags', () => {
  assert.throws(() => runSecurityKeyCommand(['remove-now'], disabled), /status, archive-can-retire, or alert-can-retire/);
  assert.throws(() => runSecurityKeyCommand(['alert-can-retire', 'old-key', '--force'], disabled), /--receiver-confirmed/);
});
