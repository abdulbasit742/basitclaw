import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createReplicaManager, ReplicaIntegrityError } from '../src/resilience/replicaManager.js';

const key = Buffer.alloc(32, 71).toString('base64');
const snapshot = {
  schemaVersion: 1,
  tenantId: 'tenant-a',
  savedAt: '2026-07-29T12:00:00.000Z',
  state: { engagements: [{ id: 'ENG-1' }], findings: [] },
  governanceEvents: []
};

function setup(t, replicaRetention = 90) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-replica-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  let current = new Date('2026-07-29T12:00:00.000Z');
  const now = () => new Date(current);
  const advance = () => { current = new Date(current.getTime() + 1000); };
  const store = createEncryptedSnapshotStore({ directory: join(root, 'primary'), keys: { current: key }, primaryKeyId: 'current', now });
  const backups = createBackupManager({ store, directory: join(root, 'backups'), retention: 10, now });
  const replicas = createReplicaManager({ store, backupManager: backups, directory: join(root, 'replicas'), retention: replicaRetention, required: true, maxLagMinutes: 120, now });
  return { root, store, backups, replicas, advance };
}

test('encrypted replica is tenant-hashed, verifiable, and idempotent', (t) => {
  const { root, store, backups, replicas } = setup(t);
  store.save('tenant-a', snapshot);
  const backup = backups.create('tenant-a');
  const first = replicas.replicate('tenant-a', backup.backupId);
  const second = replicas.replicate('tenant-a', backup.backupId);
  assert.equal(first.backupId, backup.backupId);
  assert.equal(second.idempotent, true);
  assert.equal(replicas.verify('tenant-a', backup.backupId).valid, true);
  const [tenantDirectory] = readdirSync(join(root, 'replicas'));
  assert.notEqual(tenantDirectory, 'tenant-a');
  assert.equal(replicas.tenantHealth('tenant-a').status, 'ready');
});

test('replica checksum tampering fails closed', (t) => {
  const { root, store, backups, replicas } = setup(t);
  store.save('tenant-a', snapshot);
  const backup = backups.create('tenant-a');
  replicas.replicate('tenant-a', backup.backupId);
  const [tenantDirectory] = readdirSync(join(root, 'replicas'));
  const target = join(root, 'replicas', tenantDirectory, `${backup.backupId}.snapshot.enc`);
  writeFileSync(target, `${readFileSync(target, 'utf8')}tampered`, 'utf8');
  assert.throws(() => replicas.verify('tenant-a', backup.backupId), ReplicaIntegrityError);
});

test('replica retention removes the oldest package', (t) => {
  const { store, backups, replicas, advance } = setup(t, 1);
  store.save('tenant-a', snapshot);
  const first = backups.create('tenant-a');
  replicas.replicate('tenant-a', first.backupId);
  advance();
  store.save('tenant-a', { ...snapshot, savedAt: '2026-07-29T12:00:01.000Z' });
  const second = backups.create('tenant-a');
  replicas.replicate('tenant-a', second.backupId);
  assert.deepEqual(replicas.list('tenant-a').map((item) => item.backupId), [second.backupId]);
});
