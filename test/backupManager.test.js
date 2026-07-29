import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBackupManager, BackupIntegrityError } from '../src/persistence/backupManager.js';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';

const key = Buffer.alloc(32, 7).toString('base64');
const now = () => new Date('2026-07-29T11:00:00.000Z');

function setup(t, retention = 30) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-backup-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const store = createEncryptedSnapshotStore({
    directory: join(directory, 'primary'),
    keys: { current: key },
    primaryKeyId: 'current',
    now
  });
  const manager = createBackupManager({
    store,
    directory: join(directory, 'backups'),
    retention,
    now
  });
  const snapshot = {
    schemaVersion: 1,
    tenantId: 'tenant-a',
    savedAt: now().toISOString(),
    state: {
      engagements: [{ id: 'ENG-SECRET', objective: 'Confidential payroll audit' }],
      findings: [{ id: 'FND-1' }]
    },
    governanceEvents: []
  };
  store.save('tenant-a', snapshot);
  return { directory, store, manager, snapshot };
}

test('encrypted backups are listed and verified without plaintext leakage', (t) => {
  const { directory, manager } = setup(t);
  const backup = manager.create('tenant-a', { kind: 'manual' });
  assert.equal(manager.list('tenant-a').length, 1);
  const verification = manager.verify('tenant-a', backup.backupId);
  assert.equal(verification.valid, true);
  assert.equal(verification.summary.engagementCount, 1);

  const encryptedPath = join(directory, 'backups', backup.tenantHash, `${backup.backupId}.snapshot.enc`);
  const raw = readFileSync(encryptedPath, 'utf8');
  assert.doesNotMatch(raw, /Confidential payroll audit/);
});

test('backup checksum tampering is detected before restore', (t) => {
  const { directory, manager } = setup(t);
  const backup = manager.create('tenant-a', { kind: 'manual' });
  const encryptedPath = join(directory, 'backups', backup.tenantHash, `${backup.backupId}.snapshot.enc`);
  writeFileSync(encryptedPath, `${readFileSync(encryptedPath, 'utf8')}tampered`, 'utf8');
  assert.throws(() => manager.verify('tenant-a', backup.backupId), BackupIntegrityError);
});

test('backup retention prunes the oldest recovery points', (t) => {
  const { manager } = setup(t, 2);
  manager.create('tenant-a', { kind: 'manual' });
  manager.create('tenant-a', { kind: 'scheduled' });
  const third = manager.create('tenant-a', { kind: 'safety' });
  const backups = manager.list('tenant-a');
  assert.equal(backups.length, 2);
  assert.ok(backups.some((item) => item.backupId === third.backupId));
});
