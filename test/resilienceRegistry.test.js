import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createReplicaManager } from '../src/resilience/replicaManager.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';

const key = Buffer.alloc(32, 72).toString('base64');
const now = () => new Date('2026-07-29T12:00:00.000Z');

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-resilience-registry-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const store = createEncryptedSnapshotStore({ directory: join(root, 'primary'), keys: { current: key }, primaryKeyId: 'current', now });
  const backups = createBackupManager({ store, directory: join(root, 'backups'), retention: 20, now });
  const replicas = createReplicaManager({ store, backupManager: backups, directory: join(root, 'replicas'), retention: 20, required: true, maxLagMinutes: 120, now });
  return createWorkforceAuditRegistry({ now, store, backupManager: backups, replicaManager: replicas });
}

test('backup creation replicates and a drill records governed evidence', (t) => {
  const registry = setup(t);
  registry.forTenant('tenant-a');
  const backup = registry.createTenantBackup('tenant-a', {
    actor: 'manager.one',
    reason: 'Approved resilience recovery point',
    kind: 'manual'
  });
  assert.equal(backup.replication.status, 'replicated');
  assert.equal(registry.listTenantReplicas('tenant-a').length, 1);
  const drill = registry.runRecoveryDrill('tenant-a', { actor: 'manager.one', backupId: backup.backupId });
  assert.equal(drill.outcome, 'passed');
  assert.equal(registry.getResilienceStatus('tenant-a').status, 'ready');
  assert.equal(registry.verifyGovernanceIntegrity('tenant-a').valid, true);
});

test('scheduled cycle creates a recovery point and completes a drill', (t) => {
  const registry = setup(t);
  const result = registry.runResilienceCycle(['tenant-a'], {
    actor: 'system.scheduler',
    scheduledBackupIntervalMinutes: 1440,
    drillMaxAgeDays: 30
  });
  assert.equal(result.status, 'completed');
  assert.ok(result.results[0].backupCreated);
  assert.ok(result.results[0].drillCompleted);
  assert.equal(result.results[0].resilience.status, 'ready');
});
