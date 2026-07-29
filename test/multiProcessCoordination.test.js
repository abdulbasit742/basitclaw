import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CoordinationBusyError, createFileLeaseCoordinator } from '../src/coordination/fileLeaseCoordinator.js';
import { createFencedSnapshotStore } from '../src/coordination/fencedSnapshotStore.js';
import { createCoordinatedWorkforceAuditRegistry } from '../src/coordination/coordinatedRegistry.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createWorkforceAuditRegistry } from '../src/services/workforceAuditRegistry.js';

const key = Buffer.alloc(32, 17).toString('base64');
const now = () => new Date('2026-07-29T12:00:00.000Z');

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-multiprocess-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const encryptedDirectory = join(root, 'encrypted');
  const fencedDirectory = join(root, 'fenced');
  const lockDirectory = join(root, 'locks');

  function build(instanceId) {
    const encrypted = createEncryptedSnapshotStore({
      directory: encryptedDirectory,
      keys: { current: key },
      primaryKeyId: 'current',
      now
    });
    const fenced = createFencedSnapshotStore({ store: encrypted, directory: fencedDirectory });
    const coordinator = createFileLeaseCoordinator({
      directory: lockDirectory,
      ownerId: instanceId,
      acquireTimeoutMs: 0,
      now
    });
    return {
      registry: createCoordinatedWorkforceAuditRegistry({
        coordinator,
        store: fenced,
        registryFactory: ({ store }) => createWorkforceAuditRegistry({ now, store })
      }),
      fenced
    };
  }

  return { root, lockDirectory, first: build('instance-a'), second: build('instance-b') };
}

test('independent registries preserve sequential mutations and governance history', (t) => {
  const { first, second } = setup(t);
  const engagement = first.registry.forTenant('tenant-a').createEngagement({
    universeItemId: 'HIRING-02',
    objective: 'Assess recruitment screening controls',
    scope: ['screening'],
    leadAuditor: 'Manager A',
    startDate: '2026-09-01',
    endDate: '2026-09-20',
    managementApproved: true
  }, { actor: 'manager.a' });

  assert.equal(second.registry.forTenant('tenant-a').getEngagements().length, 2);
  second.registry.forTenant('tenant-a').createFinding({
    engagementId: engagement.id,
    title: 'Screening evidence retained inconsistently',
    severity: 'high',
    owner: 'Talent Operations',
    dueDate: '2026-10-15',
    evidenceRefs: ['EV-HR-001']
  }, { actor: 'manager.b' });

  assert.equal(first.registry.forTenant('tenant-a').getFindings().length, 2);
  assert.equal(first.registry.verifyGovernanceIntegrity('tenant-a').checkedEvents, 2);
  assert.equal(first.fenced.latestFencingToken('tenant-a'), 2);
});

test('a current tenant lease blocks mutation from another process', (t) => {
  const { lockDirectory, first } = setup(t);
  const blocker = createFileLeaseCoordinator({
    directory: lockDirectory,
    ownerId: 'maintenance-owner',
    acquireTimeoutMs: 0,
    now
  });
  const lease = blocker.acquire('tenant-b');
  assert.throws(() => first.registry.forTenant('tenant-b').createEngagement({
    universeItemId: 'HIRING-02',
    objective: 'Blocked concurrent write',
    scope: ['screening'],
    leadAuditor: 'Manager A',
    startDate: '2026-10-01',
    endDate: '2026-10-20',
    managementApproved: true
  }, { actor: 'manager.a' }), CoordinationBusyError);
  lease.release();
});
