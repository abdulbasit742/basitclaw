import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../src/server.js';
import { AuthenticationError, AuthorizationError } from '../src/security/accessControl.js';
import { createSharedFileRateLimiter } from '../src/security/sharedRateLimiter.js';
import { createSecurityEventArchive } from '../src/security/securityEventArchive.js';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';

const key = Buffer.alloc(32, 61).toString('base64');
const policies = {
  burst: { limit: 100, windowMs: 60_000 }, authFailure: { limit: 10, windowMs: 60_000 },
  read: { limit: 100, windowMs: 60_000 }, write: { limit: 100, windowMs: 60_000 },
  sensitive: { limit: 100, windowMs: 60_000 }
};

function buildAccess() {
  return {
    principalCount: 2,
    tenantIds: () => ['tenant-a'],
    credentialHealth: () => ({ status: 'ready', total: 2, usable: 2 }),
    authenticate(req) {
      const value = req.headers['x-api-key'];
      if (value === 'admin-key') return { keyId: 'admin', subject: 'admin.one', tenantId: 'tenant-a', role: 'compliance_admin', permissions: ['audit:read', 'security:read'] };
      if (value === 'viewer-key') return { keyId: 'viewer', subject: 'viewer.one', tenantId: 'tenant-a', role: 'audit_viewer', permissions: ['audit:read'] };
      throw new AuthenticationError();
    },
    authorise(principal, permission) {
      if (!principal.permissions.includes(permission)) throw new AuthorizationError();
    }
  };
}

function buildRegistry() {
  const service = { getOverview: () => ({}), getUniverse: () => [], getEngagements: () => [], getFindings: () => [], getProviders: () => [] };
  return {
    forTenant: () => service,
    getPersistenceHealth: () => ({ status: 'ready', backups: { status: 'ready' }, replicas: { required: false } }),
    listGovernanceEvents: () => [], verifyGovernanceIntegrity: () => ({ valid: true }), getResilienceStatus: () => ({})
  };
}

async function start(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-server-control-plane-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const rateLimiter = createSharedFileRateLimiter({
    directory: join(root, 'rates'), policies, resolveClientAddress: () => '127.0.0.1'
  });
  const securityArchive = createSecurityEventArchive({ directory: join(root, 'archive'), encryptionKey: key, required: true });
  const securityTelemetry = createSecurityTelemetry({ pepper: 'telemetry-pepper-123456789', maxEvents: 100, archive: securityArchive });
  const scheduler = { start(){}, stop(){}, status(){ return { drillMaxAgeDays: 30, intervalMinutes: 0 }; } };
  const server = createApp({ registry: buildRegistry(), accessController: buildAccess(), resilienceScheduler: scheduler, rateLimiter, securityArchive, securityTelemetry });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return { base: `http://127.0.0.1:${server.address().port}`, root, securityTelemetry };
}

test('admin can export archived security events and public health hides paths', async (t) => {
  const { base, securityTelemetry } = await start(t);
  securityTelemetry.record({ type: 'authentication.failed', severity: 'warning', outcome: 'denied', clientAddress: '127.0.0.1' });
  const response = await fetch(`${base}/api/workforce-audit/security-archive-events`, { headers: { 'x-api-key': 'admin-key' } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.data.events.length, 1);
  const healthResponse = await fetch(`${base}/health`);
  assert.equal(healthResponse.status, 200);
  const health = await healthResponse.json();
  assert.equal(health.data.apiSecurity.rateLimiting.distributed, true);
  assert.equal(health.data.apiSecurity.telemetry.archive.status, 'ready');
  assert.equal('directory' in health.data.apiSecurity.telemetry.archive, false);
});

test('required archive integrity failure degrades readiness', async (t) => {
  const { base, root, securityTelemetry } = await start(t);
  securityTelemetry.record({ type: 'authentication.failed', severity: 'warning', outcome: 'denied', clientAddress: '127.0.0.1' });
  const segmentDir = join(root, 'archive', 'segments');
  const path = join(segmentDir, readdirSync(segmentDir)[0]);
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  envelope.hash = '0'.repeat(64);
  writeFileSync(path, `${JSON.stringify(envelope)}\n`);
  const response = await fetch(`${base}/health`);
  assert.equal(response.status, 503);
});
