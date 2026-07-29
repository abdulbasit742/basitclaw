import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { createAccessController, hashApiKeySecret } from '../src/security/accessControl.js';
import { createAdaptiveRateLimiter } from '../src/security/rateLimiter.js';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';

const salt = 'credential-salt-123456';
const adminSecret = 'admin-secret-1234567890';
const viewerSecret = 'viewer-secret-123456789';
const accessController = createAccessController({
  principals: [
    {
      keyId: 'admin-q3',
      salt,
      secretHash: hashApiKeySecret(adminSecret, salt),
      subject: 'admin.one',
      tenantId: 'tenant-a',
      role: 'compliance_admin',
      status: 'retiring'
    },
    {
      keyId: 'viewer-q3',
      salt,
      secretHash: hashApiKeySecret(viewerSecret, salt),
      subject: 'viewer.one',
      tenantId: 'tenant-a',
      role: 'audit_viewer'
    }
  ],
  allowLegacyPlaintext: false,
  now: () => new Date('2026-07-29T00:00:00Z')
});
const policies = {
  burst: { limit: 100, windowMs: 60_000 },
  authFailure: { limit: 1, windowMs: 60_000 },
  read: { limit: 100, windowMs: 60_000 },
  write: { limit: 100, windowMs: 60_000 },
  sensitive: { limit: 100, windowMs: 60_000 }
};

function buildRegistry() {
  const service = {
    getOverview: () => ({ ok: true }),
    getUniverse: () => [],
    getEngagements: () => [],
    getFindings: () => [],
    getProviders: () => []
  };
  return {
    forTenant: () => service,
    getPersistenceHealth: () => ({ status: 'ready', backups: { status: 'ready' }, replicas: { required: false } }),
    listGovernanceEvents: () => [],
    verifyGovernanceIntegrity: () => ({ valid: true }),
    getResilienceStatus: () => ({})
  };
}

async function start(t) {
  const telemetry = createSecurityTelemetry({ pepper: 'telemetry-pepper-123456789' });
  const limiter = createAdaptiveRateLimiter({ policies });
  const scheduler = { start() {}, stop() {}, status() { return { drillMaxAgeDays: 30, intervalMinutes: 0 }; } };
  const server = createApp({
    registry: buildRegistry(),
    accessController,
    rateLimiter: limiter,
    securityTelemetry: telemetry,
    resilienceScheduler: scheduler
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { base: `http://127.0.0.1:${server.address().port}`, telemetry };
}

test('retiring credentials return rotation and rate-limit headers', async (t) => {
  const { base } = await start(t);
  const response = await fetch(`${base}/api/workforce-audit/session`, {
    headers: { 'x-api-key': `admin-q3.${adminSecret}` }
  });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-api-key-rotation-required'), 'true');
  assert.equal(response.headers.get('ratelimit-limit'), '100');
  const body = await response.json();
  assert.equal(body.data.keyId, 'admin-q3');
});

test('security endpoints are admin-only and denied access is recorded', async (t) => {
  const { base, telemetry } = await start(t);
  const denied = await fetch(`${base}/api/workforce-audit/security-status`, {
    headers: { 'x-api-key': `viewer-q3.${viewerSecret}` }
  });
  assert.equal(denied.status, 403);
  assert.equal(telemetry.summary().countsByType['authorization.denied'], 1);
  const allowed = await fetch(`${base}/api/workforce-audit/security-status`, {
    headers: { 'x-api-key': `admin-q3.${adminSecret}` }
  });
  assert.equal(allowed.status, 200);
});

test('failed authentication pressure is throttled and fingerprinted', async (t) => {
  const { base, telemetry } = await start(t);
  const first = await fetch(`${base}/api/workforce-audit/session`, {
    headers: { 'x-api-key': 'bad-key-1234567890' }
  });
  const second = await fetch(`${base}/api/workforce-audit/session`, {
    headers: { 'x-api-key': 'bad-key-1234567890' }
  });
  assert.equal(first.status, 401);
  assert.equal(second.status, 429);
  assert.ok(Number(second.headers.get('retry-after')) >= 1);
  const events = telemetry.list({ limit: 10 });
  assert.ok(events.some((event) => event.type === 'authentication.failed'));
  assert.ok(events.some((event) => event.type === 'request.rate_limited'));
  assert.doesNotMatch(JSON.stringify(events), /127\.0\.0\.1/);
});
