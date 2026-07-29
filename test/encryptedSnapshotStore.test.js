import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEncryptedSnapshotStore, PersistenceError } from '../src/persistence/encryptedSnapshotStore.js';

const keyA = Buffer.alloc(32, 11).toString('base64');
const keyB = Buffer.alloc(32, 22).toString('base64');
const snapshot = {
  schemaVersion: 1,
  tenantId: 'tenant-a',
  savedAt: '2026-07-29T11:00:00.000Z',
  state: { engagements: [{ id: 'ENG-SECRET', objective: 'Highly sensitive payroll review' }], findings: [] },
  governanceEvents: []
};

function temporaryDirectory(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-store-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('snapshots are encrypted, tenant-bound, and recoverable', (t) => {
  const directory = temporaryDirectory(t);
  const store = createEncryptedSnapshotStore({ directory, keys: { 'key-a': keyA }, primaryKeyId: 'key-a' });
  store.save('tenant-a', snapshot);
  const [filename] = readdirSync(directory);
  const raw = readFileSync(join(directory, filename), 'utf8');
  assert.doesNotMatch(raw, /Highly sensitive payroll review/);
  assert.doesNotMatch(raw, /tenant-a/);
  assert.deepEqual(store.load('tenant-a'), snapshot);
  assert.equal(store.health().persistedTenantCount, 1);
});

test('missing or incorrect encryption keys fail closed', (t) => {
  const directory = temporaryDirectory(t);
  createEncryptedSnapshotStore({ directory, keys: { 'key-a': keyA }, primaryKeyId: 'key-a' }).save('tenant-a', snapshot);
  const wrongStore = createEncryptedSnapshotStore({ directory, keys: { 'key-b': keyB }, primaryKeyId: 'key-b' });
  assert.throws(() => wrongStore.load('tenant-a'), PersistenceError);
});

test('key rotation reads old snapshots and rewrites with the new primary key', (t) => {
  const directory = temporaryDirectory(t);
  createEncryptedSnapshotStore({ directory, keys: { old: keyA }, primaryKeyId: 'old' }).save('tenant-a', snapshot);
  const rotating = createEncryptedSnapshotStore({ directory, keys: { old: keyA, current: keyB }, primaryKeyId: 'current' });
  const recovered = rotating.load('tenant-a');
  rotating.save('tenant-a', recovered);
  const [filename] = readdirSync(directory);
  const envelope = JSON.parse(readFileSync(join(directory, filename), 'utf8'));
  assert.equal(envelope.keyId, 'current');
  assert.deepEqual(rotating.load('tenant-a'), snapshot);
});
