import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, utimesSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createFileMutex, SecurityControlBusyError } from '../src/security/fileMutex.js';

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-mutex-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('file mutex is exclusive across instances', (t) => {
  const root = setup(t);
  const first = createFileMutex({ directory: root, ownerId: 'one', acquireTimeoutMs: 0 });
  const second = createFileMutex({ directory: root, ownerId: 'two', acquireTimeoutMs: 0 });
  const lease = first.acquire('resource-a');
  assert.throws(() => second.acquire('resource-a'), SecurityControlBusyError);
  lease.release();
  assert.equal(second.acquire('resource-a').release(), true);
});

test('ownerless stale lock directories are recovered', (t) => {
  const root = setup(t);
  const hash = createHash('sha256').update('resource-a').digest('hex');
  const lockPath = join(root, `${hash}.lock`);
  mkdirSync(lockPath);
  const old = new Date(Date.now() - 10_000);
  utimesSync(lockPath, old, old);
  const mutex = createFileMutex({ directory: root, leaseMs: 1000, acquireTimeoutMs: 0 });
  const lease = mutex.acquire('resource-a');
  assert.equal(lease.release(), true);
});
