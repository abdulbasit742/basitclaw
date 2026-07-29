import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { runSecurityAlertCommand } from '../scripts/security-alerts.js';

const signingSecret = 'security-alert-signing-secret-1234567890';

async function environment() {
  return {
    NODE_ENV: 'test',
    WORKFORCE_AUDIT_SECURITY_ALERT_MODE: 'webhook',
    WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED: 'false',
    WORKFORCE_AUDIT_SECURITY_ALERT_WEBHOOK_URL: 'https://alerts.example.test/hook',
    WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET: signingSecret,
    WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR: await mkdtemp(resolve(tmpdir(), 'basitclaw-alert-cli-')),
    WORKFORCE_AUDIT_SECURITY_ALERT_ALLOW_HTTP: 'false',
    WORKFORCE_AUDIT_SECURITY_ALERT_ALLOW_PRIVATE_TARGETS: 'false'
  };
}

test('security alert status command reports the durable outbox', async () => {
  const result = await runSecurityAlertCommand(['status'], await environment());
  assert.equal(result.enabled, true);
  assert.equal(result.outbox.status, 'ready');
});

test('security alert CLI rejects unknown commands and invalid limits', async () => {
  const env = await environment();
  await assert.rejects(() => runSecurityAlertCommand(['unknown'], env), /Command must be/);
  await assert.rejects(() => runSecurityAlertCommand(['dispatch', '0'], env), /limit must be/);
});
