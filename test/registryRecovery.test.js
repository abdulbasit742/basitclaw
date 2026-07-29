import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createWorkforceAuditRegistry, RecoveryConflictError } from '../src/services/workforceAuditRegistry.js';

const key = Buffer.alloc(32, 13).toString('base64');
const now = () => new Date('2026-07-29T11:00:00.000Z');

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-registry-'));
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
  return { registry, store, backupManager };
}

function addEngagement(service, suffix = 'A') {
  return service.createEngagement({
    universeItemId: 'HIRING-02',
    objective: `Review ${suffix}`,
    scope: ['screening'],
    leadAuditor: 'Audit Manager',
    startDate: '2026-09-01',
    endDate: '2026-09-20',
    managementApproved: true
  }, { actor: 'manager.one' });
}

test('restore dry-runs compare state without changing the tenant', (t) => {
  const { registry } = setup(t);
  const service = registry.forTenant('tenant-a');
  addEngagement(service);
  const backup = registry.createTenantBackup('tenant-a', {
    actor: 'manager.one',
    reason: 'Monthly recovery checkpoint'
  });
  service.createFinding({
    engagementId: 'ENG-2026-006',
    title: 'Later finding',
    severity: 'medium',
    owner: 'Control Owner',
    dueDate: '2026-10-01',
    evidenceRefs: ['EV-REC-1']
  }, { actor: 'manager.one' });
  const head = registry.verifyGovernanceIntegrity('tenant-a').headHash;
  const preview = registry.restoreTenantBackup('tenant-a', backup.backupId, {
    actor: 'admin.one',
    reason: 'Validate recovery before approval',
    expectedHeadHash: head,
    dryRun: true
  });
  assert.equal(preview.dryRun, true);
  assert.equal(registry.forTenant('tenant-a').getFindings().length, 2);
});

test('confirmed restore creates a safety backup and restores business state and chain', (t) => {
  const { registry } = setup(t);
  const service = registry.forTenant('tenant-a');
  addEngagement(service);
  const backup = registry.createTenantBackup('tenant-a', {
    actor: 'manager.one',
    reason: 'Approved month-end recovery point'
  });
  service.createFinding({
    engagementId: 'ENG-2026-006',
    title: 'Later finding',
    severity: 'medium',
    owner: 'Control Owner',
    dueDate: '2026-10-01',
    evidenceRefs: ['EV-REC-1']
  }, { actor: 'manager.one' });

  const head = registry.verifyGovernanceIntegrity('tenant-a').headHash;
  const result = registry.restoreTenantBackup('tenant-a', backup.backupId, {
    actor: 'admin.one',
    reason: 'Recover to approved month-end state',
    expectedHeadHash: head,
    confirmation: `RESTORE ${backup.backupId}`,
    dryRun: false
  });

  assert.equal(result.dryRun, false);
  assert.equal(registry.forTenant('tenant-a').getFindings().length, 1);
  assert.equal(result.governanceIntegrity.valid, true);
  assert.equal(registry.listTenantBackups('tenant-a').length, 2);
  const events = registry.listGovernanceEvents('tenant-a');
  assert.equal(events.at(-1).action, 'backup.restored');
});

test('stale governance heads prevent destructive recovery', (t) => {
  const { registry } = setup(t);
  const backup = registry.createTenantBackup('tenant-a', {
    actor: 'manager.one',
    reason: 'Initial recovery checkpoint'
  });
  assert.throws(() => registry.restoreTenantBackup('tenant-a', backup.backupId, {
    actor: 'admin.one',
    reason: 'Attempt using stale governance version',
    expectedHeadHash: 'stale-head',
    confirmation: `RESTORE ${backup.backupId}`,
    dryRun: false
  }), RecoveryConflictError);
});
