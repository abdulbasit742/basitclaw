import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createAccessController } from '../src/security/accessControl.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';
import { createApp } from '../src/server.js';

const now = () => new Date('2026-07-29T11:00:00.000Z');
const key = Buffer.alloc(32, 21).toString('base64');
const managerKey = 'manager-key-123456789';
const adminKey = 'admin-key-12345678901';

async function start(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-http-recovery-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const store = createEncryptedSnapshotStore({
    directory: join(directory, 'primary'),
    keys: { current: key },
    primaryKeyId: 'current',
    now
  });
  const backupManager = createBackupManager({
    store,
    directory: join(directory, 'backups'),
    retention: 10,
    now
  });
  const registry = createWorkforceAuditRegistry({ now, store, backupManager });
  const accessController = createAccessController({ principals: [
    { apiKey: managerKey, subject: 'manager.one', tenantId: 'tenant-a', role: 'audit_manager' },
    { apiKey: adminKey, subject: 'admin.one', tenantId: 'tenant-a', role: 'compliance_admin' }
  ] });
  const server = createApp({ registry, accessController });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

test('backup endpoints enforce manager creation and admin-only restore', async (t) => {
  const base = await start(t);
  const create = await fetch(`${base}/api/workforce-audit/backups`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ reason: 'Approved operational recovery point' })
  });
  const created = await create.json();
  assert.equal(create.status, 201);

  const managerRestore = await fetch(`${base}/api/workforce-audit/backups/${created.data.backupId}/restore`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ reason: 'Attempt restore without admin role', expectedHeadHash: null })
  });
  assert.equal(managerRestore.status, 403);

  const integrity = await fetch(`${base}/api/workforce-audit/governance-integrity`, {
    headers: { 'x-api-key': adminKey }
  }).then((response) => response.json());

  const dryRun = await fetch(`${base}/api/workforce-audit/backups/${created.data.backupId}/restore`, {
    method: 'POST',
    headers: { 'x-api-key': adminKey, 'content-type': 'application/json' },
    body: JSON.stringify({
      reason: 'Validate recovery package before approval',
      expectedHeadHash: integrity.data.headHash,
      dryRun: true
    })
  });
  const preview = await dryRun.json();
  assert.equal(dryRun.status, 200);
  assert.equal(preview.data.dryRun, true);
});

test('backup verification reports integrity and recovery-point summary', async (t) => {
  const base = await start(t);
  const created = await fetch(`${base}/api/workforce-audit/backups`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: JSON.stringify({ reason: 'Quarterly disaster recovery evidence' })
  }).then((response) => response.json());

  const verification = await fetch(`${base}/api/workforce-audit/backups/${created.data.backupId}/verify`, {
    method: 'POST',
    headers: { 'x-api-key': managerKey, 'content-type': 'application/json' },
    body: '{}'
  });
  const payload = await verification.json();
  assert.equal(verification.status, 200);
  assert.equal(payload.data.valid, true);
  assert.equal(payload.data.summary.engagementCount, 1);
});
