import { createHash, randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { hostname } from 'node:os';
import { resolve } from 'node:path';

export class SecurityControlBusyError extends Error {
  constructor(message = 'The shared security control is busy.', details = {}) {
    super(message);
    this.name = 'SecurityControlBusyError';
    this.code = 'SECURITY_CONTROL_BUSY';
    this.details = details;
  }
}

export class SecurityControlUnavailableError extends Error {
  constructor(message = 'The shared security control is unavailable.', details = {}) {
    super(message);
    this.name = 'SecurityControlUnavailableError';
    this.code = 'SECURITY_CONTROL_UNAVAILABLE';
    this.details = details;
  }
}

export function createFileMutex({
  directory,
  ownerId = `${hostname()}:${process.pid}:${randomUUID()}`,
  leaseMs = 5_000,
  acquireTimeoutMs = 1_000,
  retryMs = 10,
  now = () => new Date()
} = {}) {
  const root = resolve(String(directory ?? ''));
  if (!String(directory ?? '').trim()) throw new TypeError('A file-mutex directory is required.');
  const safeLeaseMs = integer(leaseMs, 'leaseMs', 100, 300_000);
  const safeTimeoutMs = integer(acquireTimeoutMs, 'acquireTimeoutMs', 0, 60_000);
  const safeRetryMs = integer(retryMs, 'retryMs', 1, 1_000);
  const safeOwnerId = String(ownerId).slice(0, 256);
  ensureDirectory(root);

  function acquire(resourceKey) {
    const resourceHash = createHash('sha256').update(String(resourceKey)).digest('hex');
    const lockDirectory = resolve(root, `${resourceHash}.lock`);
    const ownerPath = resolve(lockDirectory, 'owner.json');
    const deadline = Date.now() + safeTimeoutMs;

    while (true) {
      const token = randomUUID();
      const current = now();
      try {
        mkdirSync(lockDirectory, { mode: 0o700 });
        const owner = {
          version: 1,
          token,
          ownerId: safeOwnerId,
          resourceHash,
          acquiredAt: current.toISOString(),
          expiresAt: new Date(current.getTime() + safeLeaseMs).toISOString()
        };
        writeFileSync(ownerPath, `${JSON.stringify(owner)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
        return createHandle({ lockDirectory, ownerPath, owner, now });
      } catch (error) {
        if (error?.code !== 'EEXIST') {
          cleanupOwnedDirectory(lockDirectory, ownerPath, token);
          throw unavailable(error, resourceHash);
        }
        const observed = inspectLock(lockDirectory, ownerPath, now, safeLeaseMs);
        if (observed.stale) {
          quarantine(lockDirectory);
          continue;
        }
        if (Date.now() >= deadline) {
          throw new SecurityControlBusyError('The shared security control lock could not be acquired before the timeout.', {
            resourceHash,
            retryAfterMs: observed.retryAfterMs
          });
        }
        sleep(safeRetryMs);
      }
    }
  }

  function withLock(resourceKey, operation) {
    if (typeof operation !== 'function') throw new TypeError('A file-mutex operation is required.');
    const handle = acquire(resourceKey);
    try {
      handle.assertOwned();
      const result = operation(handle);
      handle.assertOwned();
      return result;
    } finally {
      handle.release();
    }
  }

  function health() {
    try {
      ensureDirectory(root);
      const probe = resolve(root, `.probe-${randomUUID()}`);
      mkdirSync(probe, { mode: 0o700 });
      rmSync(probe, { recursive: true, force: true });
      return { status: 'ready', mode: 'atomic-directory-mutex', directory: root, leaseMs: safeLeaseMs };
    } catch (error) {
      return { status: 'unavailable', mode: 'atomic-directory-mutex', directory: root, error: error.message };
    }
  }

  return { acquire, withLock, health, directory: root, ownerId: safeOwnerId };
}

function createHandle({ lockDirectory, ownerPath, owner, now }) {
  let released = false;
  function readCurrentOwner() {
    try { return JSON.parse(readFileSync(ownerPath, 'utf8')); } catch { return null; }
  }
  function assertOwned() {
    const current = readCurrentOwner();
    if (!current || current.token !== owner.token || new Date(current.expiresAt).getTime() <= now().getTime()) {
      const error = new SecurityControlUnavailableError('The shared security control lock was lost.', {
        resourceHash: owner.resourceHash,
        reason: 'lock_lost'
      });
      error.code = 'SECURITY_CONTROL_LOCK_LOST';
      throw error;
    }
    return true;
  }
  function release() {
    if (released) return false;
    released = true;
    const current = readCurrentOwner();
    if (!current || current.token !== owner.token) return false;
    rmSync(lockDirectory, { recursive: true, force: true });
    return true;
  }
  return Object.freeze({ ...owner, assertOwned, release });
}

function inspectLock(lockDirectory, ownerPath, now, leaseMs) {
  try {
    const owner = JSON.parse(readFileSync(ownerPath, 'utf8'));
    const remaining = new Date(owner.expiresAt).getTime() - now().getTime();
    return { stale: !Number.isFinite(remaining) || remaining <= 0, retryAfterMs: Math.max(1, remaining) };
  } catch {
    try {
      const age = now().getTime() - statSync(lockDirectory).mtimeMs;
      return { stale: age >= leaseMs, retryAfterMs: Math.max(1, leaseMs - age) };
    } catch {
      return { stale: true, retryAfterMs: 1 };
    }
  }
}

function quarantine(lockDirectory) {
  if (!existsSync(lockDirectory)) return;
  const target = `${lockDirectory}.stale-${Date.now()}-${randomUUID()}`;
  try {
    renameSync(lockDirectory, target);
    rmSync(target, { recursive: true, force: true });
  } catch (error) {
    if (!['ENOENT', 'EEXIST'].includes(error?.code)) throw unavailable(error, null);
  }
}

function cleanupOwnedDirectory(lockDirectory, ownerPath, token) {
  try {
    const current = JSON.parse(readFileSync(ownerPath, 'utf8'));
    if (current.token === token) rmSync(lockDirectory, { recursive: true, force: true });
  } catch { /* ownerless directories age into stale takeover */ }
}

function ensureDirectory(directory) {
  try { mkdirSync(directory, { recursive: true, mode: 0o700 }); } catch (error) { throw unavailable(error, null); }
}

function unavailable(error, resourceHash) {
  if (error instanceof SecurityControlUnavailableError) return error;
  return new SecurityControlUnavailableError('The shared security control filesystem operation failed.', {
    resourceHash,
    cause: error?.code ?? error?.message ?? 'unknown'
  });
}

function sleep(milliseconds) {
  const buffer = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(buffer), 0, 0, milliseconds);
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}
