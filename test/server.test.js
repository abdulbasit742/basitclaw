import test from 'node:test';
import assert from 'node:assert/strict';
import { createAccessController } from '../src/security/accessControl.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';
import { createApp } from '../src/server.js';

const keys = {
  viewer: 'viewer-key-1234567890',
  managerA: 'manager-a-key-12345678',
  managerB: 'manager-b-key-12345678'
};

function createTestApp() {
  const accessController = createAccessController({ principals: [
    { apiKey: keys.viewer, subject: 'viewer.one', tenantId: 'tenant-a', role: 'audit_viewer' },
    { apiKey: keys.managerA, subject: 'manager.a', tenantId: 'tenant-a', role: 'audit_manager' },
    { apiKey: keys.managerB, subject: 'manager.b', tenantId: 'tenant-b', role: 'audit_manager' }
  ] });
  const now = () => new Date('2026-07-29T11:00:00.000Z');
  return createApp({ accessController, registry: createWorkforceAuditRegistry({ now }) });
}

async function start(t) {
  const server = createTestApp();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

test('health is public while audit APIs require authentication', async (t) => {
  const base = await start(t);
  const health = await fetch(`${base}/health`);
  assert.equal(health.status, 200);
  assert.ok(health.headers.get('x-request-id'));

  const denied = await fetch(`${base}/api/workforce-audit/overview`);
  assert.equal(denied.status, 401);
  assert.match(denied.headers.get('www-authenticate'), /ApiKey/);
});

test('viewer can read but cannot create engagements', async (t) => {
  const base = await start(t);
  const read = await fetch(`${base}/api/workforce-audit/overview`, { headers: { 'x-api-key': keys.viewer } });
  assert.equal(read.status, 200);

  const write = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST', headers: { 'x-api-key': keys.viewer, 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(write.status, 403);
});

test('tenant mutations and governance history remain isolated', async (t) => {
  const base = await start(t);
  const createResponse = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST',
    headers: { 'x-api-key': keys.managerA, 'content-type': 'application/json' },
    body: JSON.stringify({
      universeItemId: 'HIRING-02', objective: 'Assess recruitment screening controls', scope: ['screening', 'offer approvals'], leadAuditor: 'Manager A', startDate: '2026-09-01', endDate: '2026-09-20', managementApproved: true
    })
  });
  assert.equal(createResponse.status, 201);

  const [engagementsA, engagementsB, eventsA, eventsB] = await Promise.all([
    fetch(`${base}/api/workforce-audit/engagements`, { headers: { 'x-api-key': keys.managerA } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/engagements`, { headers: { 'x-api-key': keys.managerB } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/governance-events`, { headers: { 'x-api-key': keys.managerA } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/governance-events`, { headers: { 'x-api-key': keys.managerB } }).then((r) => r.json())
  ]);

  assert.equal(engagementsA.data.length, 2);
  assert.equal(engagementsB.data.length, 1);
  assert.equal(eventsA.data.length, 1);
  assert.equal(eventsB.data.length, 0);
  assert.equal(eventsA.data[0].actor, 'manager.a');
});

test('tenant override attempts are forbidden and integrity endpoint verifies the chain', async (t) => {
  const base = await start(t);
  const mismatch = await fetch(`${base}/api/workforce-audit/overview`, { headers: { 'x-api-key': keys.managerA, 'x-tenant-id': 'tenant-b' } });
  assert.equal(mismatch.status, 403);

  const integrity = await fetch(`${base}/api/workforce-audit/governance-integrity`, { headers: { 'x-api-key': keys.managerA } });
  const payload = await integrity.json();
  assert.equal(integrity.status, 200);
  assert.equal(payload.data.valid, true);
});

test('dashboard route serves the API-key aware assurance page', async (t) => {
  const base = await start(t);
  const response = await fetch(`${base}/dashboard/workforce-audit`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /Workforce Audit Assurance/);
  assert.match(html, /x-api-key/);
});
