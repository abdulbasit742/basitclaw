import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEncryptedSnapshotStore, PersistenceError } from '../src/persistence/encryptedSnapshotStore.js';
import { createAccessController } from '../src/security/accessControl.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';
import { createApp } from '../src/server.js';

const keys = {
  viewer: 'viewer-key-1234567890',
  managerA: 'manager-a-key-12345678',
  managerB: 'manager-b-key-12345678'
};
const encryptionKey = Buffer.alloc(32, 44).toString('base64');

function createTestApp(t, storeOverride) {
  const accessController = createAccessController({ principals: [
    { apiKey: keys.viewer, subject: 'viewer.one', tenantId: 'tenant-a', role: 'audit_viewer' },
    { apiKey: keys.managerA, subject: 'manager.a', tenantId: 'tenant-a', role: 'audit_manager' },
    { apiKey: keys.managerB, subject: 'manager.b', tenantId: 'tenant-b', role: 'audit_manager' }
  ] });
  const now = () => new Date('2026-07-29T11:00:00.000Z');
  let store = storeOverride;
  if (!store) {
    const directory = mkdtempSync(join(tmpdir(), 'basitclaw-server-'));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    store = createEncryptedSnapshotStore({ directory, keys: { current: encryptionKey }, primaryKeyId: 'current', now });
  }
  return createApp({ accessController, registry: createWorkforceAuditRegistry({ now, store }) });
}

async function start(t, storeOverride) {
  const server = createTestApp(t, storeOverride);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

test('health is public and reports encrypted persistence readiness', async (t) => {
  const base = await start(t);
  const response = await fetch(`${base}/health`);
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.data.persistence.mode, 'encrypted-file');
  assert.ok(response.headers.get('x-request-id'));
});

test('audit APIs require authentication and viewer writes are forbidden', async (t) => {
  const base = await start(t);
  assert.equal((await fetch(`${base}/api/workforce-audit/overview`)).status, 401);
  const write = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST', headers: { 'x-api-key': keys.viewer, 'content-type': 'application/json' }, body: '{}'
  });
  assert.equal(write.status, 403);
});

test('tenant mutations and governance history remain isolated', async (t) => {
  const base = await start(t);
  const created = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST',
    headers: { 'x-api-key': keys.managerA, 'content-type': 'application/json' },
    body: JSON.stringify({ universeItemId: 'HIRING-02', objective: 'Assess recruitment screening controls', scope: ['screening'], leadAuditor: 'Manager A', startDate: '2026-09-01', endDate: '2026-09-20', managementApproved: true })
  });
  assert.equal(created.status, 201);
  const [a, b, eventsA, eventsB] = await Promise.all([
    fetch(`${base}/api/workforce-audit/engagements`, { headers: { 'x-api-key': keys.managerA } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/engagements`, { headers: { 'x-api-key': keys.managerB } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/governance-events`, { headers: { 'x-api-key': keys.managerA } }).then((r) => r.json()),
    fetch(`${base}/api/workforce-audit/governance-events`, { headers: { 'x-api-key': keys.managerB } }).then((r) => r.json())
  ]);
  assert.equal(a.data.length, 2);
  assert.equal(b.data.length, 1);
  assert.equal(eventsA.data.length, 1);
  assert.equal(eventsB.data.length, 0);
});

test('persistence health is governance-restricted', async (t) => {
  const base = await start(t);
  const viewer = await fetch(`${base}/api/workforce-audit/persistence-health`, { headers: { 'x-api-key': keys.viewer } });
  assert.equal(viewer.status, 403);
  const manager = await fetch(`${base}/api/workforce-audit/persistence-health`, { headers: { 'x-api-key': keys.managerA } });
  const payload = await manager.json();
  assert.equal(manager.status, 200);
  assert.equal(payload.data.status, 'ready');
});

test('durable write failures return 503 and do not expose a false success', async (t) => {
  const failingStore = {
    load: () => null,
    save: () => { throw new PersistenceError('disk offline'); },
    health: () => ({ status: 'unavailable', mode: 'encrypted-file', primaryKeyId: 'current', configuredKeyIds: ['current'], persistedTenantCount: 0 })
  };
  const base = await start(t, failingStore);
  const response = await fetch(`${base}/api/workforce-audit/engagements`, {
    method: 'POST',
    headers: { 'x-api-key': keys.managerA, 'content-type': 'application/json' },
    body: JSON.stringify({ universeItemId: 'HIRING-02', objective: 'Assess recruitment screening controls', scope: ['screening'], leadAuditor: 'Manager A', startDate: '2026-09-01', endDate: '2026-09-20', managementApproved: true })
  });
  const payload = await response.json();
  assert.equal(response.status, 503);
  assert.equal(payload.code, 'PERSISTENCE_UNAVAILABLE');
});

test('dashboard route serves the encrypted-persistence assurance page', async (t) => {
  const base = await start(t);
  const response = await fetch(`${base}/dashboard/workforce-audit`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /Encrypted storage/);
});
