import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createReplicaManager } from '../src/resilience/replicaManager.js';
import { createResilienceScheduler } from '../src/resilience/resilienceScheduler.js';
import { createAccessController } from '../src/security/accessControl.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';
import { createApp } from '../src/server.js';

const key = Buffer.alloc(32, 73).toString('base64');
const managerKey = 'manager-key-123456789';
const adminKey = 'admin-key-12345678901';
const now = () => new Date('2026-07-29T12:00:00.000Z');

async function start(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-server-resilience-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const store = createEncryptedSnapshotStore({ directory: join(root, 'primary'), keys: { current: key }, primaryKeyId: 'current', now });
  const backups = createBackupManager({ store, directory: join(root, 'backups'), retention: 20, now });
  const replicas = createReplicaManager({ store, backupManager: backups, directory: join(root, 'replicas'), retention: 20, required: true, maxLagMinutes: 120, now });
  const registry = createWorkforceAuditRegistry({ now, store, backupManager: backups, replicaManager: replicas });
  const accessController = createAccessController({ principals: [
    { apiKey: managerKey, subject: 'manager.one', tenantId: 'tenant-a', role: 'audit_manager' },
    { apiKey: adminKey, subject: 'admin.one', tenantId: 'tenant-a', role: 'compliance_admin' }
  ] });
  const resilienceScheduler = createResilienceScheduler({ registry, tenantIds: ['tenant-a'], intervalMinutes: 0 });
  const server = createApp({ registry, accessController, resilienceScheduler });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

test('manager can create and verify replicas and run a drill', async (t) => {
  const base = await start(t);
  const backup = await fetch(`${base}/api/workforce-audit/backups`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ reason: 'Approved replicated recovery point' })
  }).then((response) => response.json());
  assert.equal(backup.data.replication.status, 'replicated');

  const replicas = await fetch(`${base}/api/workforce-audit/replicas`, { headers: { 'x-api-key': managerKey } });
  assert.equal(replicas.status, 200);

  const drill = await fetch(`${base}/api/workforce-audit/recovery-drills`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ backupId: backup.data.backupId })
  });
  const drillPayload = await drill.json();
  assert.equal(drill.status, 201);
  assert.equal(drillPayload.data.outcome, 'passed');
});

test('manual resilience cycle remains compliance-admin only', async (t) => {
  const base = await start(t);
  const manager = await fetch(`${base}/api/workforce-audit/resilience-cycle`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: '{}'
  });
  assert.equal(manager.status, 403);

  const admin = await fetch(`${base}/api/workforce-audit/resilience-cycle`, {
    method: 'POST',
    headers: { 'x-api-key': adminKey, 'content-type': 'application/json' },
    body: JSON.stringify({ scheduledBackupIntervalMinutes: 1440, drillMaxAgeDays: 30 })
  });
  const payload = await admin.json();
  assert.equal(admin.status, 200);
  assert.equal(payload.data.status, 'completed');
});
