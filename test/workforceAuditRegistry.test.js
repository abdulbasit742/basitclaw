import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';

const key = Buffer.alloc(32, 33).toString('base64');
const now = () => new Date('2026-07-29T11:00:00.000Z');

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-registry-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return createEncryptedSnapshotStore({ directory, keys: { current: key }, primaryKeyId: 'current', now });
}

test('registry restores encrypted tenant state and governance history after restart', (t) => {
  const store = setup(t);
  const firstRegistry = createWorkforceAuditRegistry({ now, store });
  firstRegistry.forTenant('tenant-a').createEngagement({
    universeItemId: 'HIRING-02', objective: 'Assess recruitment screening controls', scope: ['screening'], leadAuditor: 'Manager A', startDate: '2026-09-01', endDate: '2026-09-20', managementApproved: true
  }, { actor: 'manager.a' });
  const restarted = createWorkforceAuditRegistry({ now, store });
  assert.equal(restarted.forTenant('tenant-a').getEngagements().length, 2);
  assert.equal(restarted.listGovernanceEvents('tenant-a').length, 1);
  assert.equal(restarted.verifyGovernanceIntegrity('tenant-a').valid, true);
});

test('registry keeps persisted tenant snapshots isolated', (t) => {
  const store = setup(t);
  const registry = createWorkforceAuditRegistry({ now, store });
  registry.forTenant('tenant-a').addFieldworkPlaceholder('ENG-2026-004', {
    title: 'Tenant A evidence', reason: 'Awaiting source', owner: 'Manager A', expiresAt: '2026-08-15'
  }, { actor: 'manager.a' });
  assert.equal(registry.forTenant('tenant-a').getEngagements()[0].fieldworkPlaceholders.length, 1);
  assert.equal(registry.forTenant('tenant-b').getEngagements()[0].fieldworkPlaceholders.length, 0);
  assert.equal(store.health().persistedTenantCount, 1);
});
