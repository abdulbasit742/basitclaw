import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  CoordinationBusyError,
  CoordinationLostError,
  createFileLeaseCoordinator
} from '../src/coordination/fileLeaseCoordinator.js';

function setup(t) {
  const directory = mkdtempSync(join(tmpdir(), 'basitclaw-lease-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('tenant leases are exclusive and fencing tokens increase', (t) => {
  const directory = setup(t);
  const first = createFileLeaseCoordinator({ directory, ownerId: 'instance-a', acquireTimeoutMs: 0 });
  const second = createFileLeaseCoordinator({ directory, ownerId: 'instance-b', acquireTimeoutMs: 0 });
  const leaseA = first.acquire('tenant-a');
  assert.equal(leaseA.fencingToken, 1);
  assert.throws(() => second.acquire('tenant-a'), CoordinationBusyError);
  assert.equal(leaseA.release(), true);
  const leaseB = second.acquire('tenant-a');
  assert.equal(leaseB.fencingToken, 2);
  leaseB.release();
});

test('expired leases are taken over and stale handles lose authority', (t) => {
  const directory = setup(t);
  let current = new Date('2026-07-29T12:00:00.000Z');
  const now = () => new Date(current);
  const first = createFileLeaseCoordinator({ directory, ownerId: 'instance-a', leaseMs: 1000, acquireTimeoutMs: 0, now });
  const second = createFileLeaseCoordinator({ directory, ownerId: 'instance-b', leaseMs: 1000, acquireTimeoutMs: 0, now });
  const leaseA = first.acquire('tenant-a');
  current = new Date('2026-07-29T12:00:02.000Z');
  const leaseB = second.acquire('tenant-a');
  assert.equal(leaseB.fencingToken, 2);
  assert.throws(() => leaseA.assertValid(), CoordinationLostError);
  assert.equal(leaseA.release(), false);
  leaseB.release();
});
