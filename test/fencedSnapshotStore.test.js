import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEncryptedSnapshotStore } from '../src/persistence/encryptedSnapshotStore.js';
import { createFencedSnapshotStore, FencingRejectedError } from '../src/coordination/fencedSnapshotStore.js';

const key = Buffer.alloc(32, 8).toString('base64');
const snapshot = (label) => ({
  schemaVersion: 1,
  tenantId: 'tenant-a',
  savedAt: '2026-07-29T12:00:00.000Z',
  state: { engagements: [{ id: label }], findings: [] },
  governanceEvents: []
});

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-fenced-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const base = createEncryptedSnapshotStore({
    directory: join(directory, 'base'),
    keys: { current: key },
    primaryKeyId: 'current'
  });
  return createFencedSnapshotStore({ store: base, directory: join(directory, 'fenced') });
}

test('higher fencing tokens supersede lower versions', (t) => {
  const store = setup(t);
  store.save('tenant-a', snapshot('token-1'), { fencingToken: 1 });
  store.save('tenant-a', snapshot('token-2'), { fencingToken: 2 });
  assert.equal(store.load('tenant-a').state.engagements[0].id, 'token-2');
  assert.throws(() => store.save('tenant-a', snapshot('stale'), { fencingToken: 1 }), FencingRejectedError);
  assert.equal(store.load('tenant-a').state.engagements[0].id, 'token-2');
});

test('restore payloads are re-encrypted under the current fence', (t) => {
  const store = setup(t);
  store.save('tenant-a', snapshot('before'), { fencingToken: 1 });
  const encrypted = store.readEncrypted('tenant-a').serialized;
  store.save('tenant-a', snapshot('after'), { fencingToken: 2 });
  store.writeEncrypted('tenant-a', encrypted, { fencingToken: 3 });
  assert.equal(store.latestFencingToken('tenant-a'), 3);
  assert.equal(store.load('tenant-a').state.engagements[0].id, 'before');
});
