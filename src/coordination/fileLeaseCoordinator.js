import { randomBytes, randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { hostname } from 'node:os';
import { dirname, resolve } from 'node:path';
import { hashTenantIdentifier } from '../persistence/encryptedSnapshotStore.js';

const OWNER_FILE = 'owner.json';
const DEFAULT_LEASE_MS = 30_000;
const DEFAULT_ACQUIRE_TIMEOUT_MS = 1_000;
const DEFAULT_RETRY_MS = 20;

export class CoordinationBusyError extends Error {
  constructor(message = 'Another process currently owns the tenant write lease.', details = {}) {
    super(message);
    this.name = 'CoordinationBusyError';
    this.code = 'WRITE_COORDINATION_BUSY';
    this.details = details;
  }
}

export class CoordinationLostError extends Error {
  constructor(message = 'The tenant write lease is no longer owned by this process.', details = {}) {
    super(message);
    this.name = 'CoordinationLostError';
    this.code = 'WRITE_COORDINATION_LOST';
    this.details = details;
  }
}

export class CoordinationUnavailableError extends Error {
  constructor(message = 'The tenant write-coordination subsystem is unavailable.', details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'CoordinationUnavailableError';
    this.code = 'WRITE_COORDINATION_UNAVAILABLE';
    this.details = details;
  }
}

export function createFileLeaseCoordinator({
  directory = '.runtime-data/workforce-audit-coordination',
  ownerId = process.env.WORKFORCE_AUDIT_INSTANCE_ID || `${hostname()}-${process.pid}-${randomUUID()}`,
  leaseMs = DEFAULT_LEASE_MS,
  acquireTimeoutMs = DEFAULT_ACQUIRE_TIMEOUT_MS,
  retryMs = DEFAULT_RETRY_MS,
  now = () => new Date(),
  sleep = blockingSleep
} = {}) {
  const absoluteDirectory = resolve(String(directory));
  const safeOwnerId = validateOwnerId(ownerId);
  const safeLeaseMs = normaliseInteger(leaseMs, 'leaseMs', 1_000, 300_000);
  const safeAcquireTimeoutMs = normaliseInteger(acquireTimeoutMs, 'acquireTimeoutMs', 0, 60_000);
  const safeRetryMs = normaliseInteger(retryMs, 'retryMs', 1, 5_000);

  function acquire(tenantId, options = {}) {
    validateTenantId(tenantId);
    const timeoutMs = options.acquireTimeoutMs === undefined
      ? safeAcquireTimeoutMs
      : normaliseInteger(options.acquireTimeoutMs, 'acquireTimeoutMs', 0, 60_000);
    const deadline = now().getTime() + timeoutMs;

    mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
    const path = leaseDirectory(absoluteDirectory, tenantId);

    while (true) {
      try {
        mkdirSync(path, { mode: 0o700 });
        const fencingToken = nextFencingToken(absoluteDirectory, tenantId);
        const acquiredAt = now();
        const record = {
          format: 'basitclaw-workforce-audit-file-lease',
          version: 1,
          tenantHash: hashTenantIdentifier(tenantId),
          ownerId: safeOwnerId,
          pid: process.pid,
          hostname: hostname(),
          fencingToken,
          acquiredAt: acquiredAt.toISOString(),
          heartbeatAt: acquiredAt.toISOString(),
          expiresAt: new Date(acquiredAt.getTime() + safeLeaseMs).toISOString()
        };
        atomicWrite(resolve(path, OWNER_FILE), `${JSON.stringify(record)}\n`);
        return createLeaseHandle(tenantId, path, record);
      } catch (error) {
        if (error?.code !== 'EEXIST') {
          throw new CoordinationUnavailableError('The tenant write lease could not be acquired.', {
            tenantId,
            directory: absoluteDirectory
          }, error);
        }

        const current = readOwner(path);
        if (current && isExpired(current, now())) {
          tryTakeOverStaleLease(path, tenantId, current);
          continue;
        }

        if (now().getTime() >= deadline) {
          throw new CoordinationBusyError(undefined, {
            tenantId,
            ownerId: current?.ownerId ?? null,
            fencingToken: current?.fencingToken ?? null,
            expiresAt: current?.expiresAt ?? null,
            retryAfterMs: current?.expiresAt
              ? Math.max(1, new Date(current.expiresAt).getTime() - now().getTime())
              : safeRetryMs
          });
        }
        sleep(Math.min(safeRetryMs, Math.max(1, deadline - now().getTime())));
      }
    }
  }

  function withLease(tenantId, operation, options = {}) {
    if (typeof operation !== 'function') throw new TypeError('A coordinated operation function is required.');
    const lease = acquire(tenantId, options);
    try {
      lease.assertValid();
      const result = operation(lease);
      lease.assertValid();
      return result;
    } finally {
      lease.release();
    }
  }

  function inspect(tenantId) {
    validateTenantId(tenantId);
    const path = leaseDirectory(absoluteDirectory, tenantId);
    const owner = readOwner(path);
    if (!owner) return { status: 'available', tenantId, owner: null };
    return {
      status: isExpired(owner, now()) ? 'stale' : 'leased',
      tenantId,
      owner: structuredClone(owner)
    };
  }

  function health() {
    try {
      mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
      let activeLeaseCount = 0;
      let staleLeaseCount = 0;
      for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
        if (!entry.isDirectory() || !entry.name.endsWith('.lease')) continue;
        const owner = readOwner(resolve(absoluteDirectory, entry.name));
        if (!owner || isExpired(owner, now())) staleLeaseCount += 1;
        else activeLeaseCount += 1;
      }
      return {
        status: 'ready',
        enabled: true,
        mode: 'file-lease-fencing',
        directory: absoluteDirectory,
        ownerId: safeOwnerId,
        leaseMs: safeLeaseMs,
        acquireTimeoutMs: safeAcquireTimeoutMs,
        activeLeaseCount,
        staleLeaseCount
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        mode: 'file-lease-fencing',
        directory: absoluteDirectory,
        ownerId: safeOwnerId,
        leaseMs: safeLeaseMs,
        acquireTimeoutMs: safeAcquireTimeoutMs,
        activeLeaseCount: 0,
        staleLeaseCount: 0,
        error: error.message
      };
    }
  }

  function createLeaseHandle(tenantId, path, initialRecord) {
    let released = false;
    const identity = {
      ownerId: initialRecord.ownerId,
      fencingToken: initialRecord.fencingToken
    };

    function assertValid() {
      if (released) throw new CoordinationLostError('The tenant write lease has already been released.', { tenantId, ...identity });
      const current = readOwner(path);
      if (!sameLease(current, identity) || isExpired(current, now())) {
        throw new CoordinationLostError(undefined, {
          tenantId,
          expectedOwnerId: identity.ownerId,
          expectedFencingToken: identity.fencingToken,
          actualOwnerId: current?.ownerId ?? null,
          actualFencingToken: current?.fencingToken ?? null,
          expiresAt: current?.expiresAt ?? null
        });
      }
      return true;
    }

    function heartbeat() {
      assertValid();
      const currentTime = now();
      const updated = {
        ...readOwner(path),
        heartbeatAt: currentTime.toISOString(),
        expiresAt: new Date(currentTime.getTime() + safeLeaseMs).toISOString()
      };
      atomicWrite(resolve(path, OWNER_FILE), `${JSON.stringify(updated)}\n`);
      assertValid();
      return structuredClone(updated);
    }

    function release() {
      if (released) return false;
      released = true;
      const current = readOwner(path);
      if (!sameLease(current, identity)) return false;
      try {
        rmSync(path, { recursive: true, force: true });
        fsyncDirectory(dirname(path));
        return true;
      } catch (error) {
        throw new CoordinationUnavailableError('The tenant write lease could not be released.', { tenantId, ...identity }, error);
      }
    }

    return Object.freeze({
      tenantId,
      ownerId: identity.ownerId,
      fencingToken: identity.fencingToken,
      acquiredAt: initialRecord.acquiredAt,
      expiresAt: initialRecord.expiresAt,
      assertValid,
      heartbeat,
      release
    });
  }

  function tryTakeOverStaleLease(path, tenantId, current) {
    const quarantine = `${path}.stale.${process.pid}.${randomBytes(6).toString('hex')}`;
    try {
      renameSync(path, quarantine);
      rmSync(quarantine, { recursive: true, force: true });
      fsyncDirectory(dirname(path));
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'EEXIST') return;
      throw new CoordinationUnavailableError('A stale tenant write lease could not be quarantined.', {
        tenantId,
        staleOwnerId: current?.ownerId ?? null,
        staleFencingToken: current?.fencingToken ?? null
      }, error);
    }
  }

  return {
    enabled: true,
    mode: 'file-lease-fencing',
    directory: absoluteDirectory,
    ownerId: safeOwnerId,
    leaseMs: safeLeaseMs,
    acquire,
    withLease,
    inspect,
    health
  };
}

export function createNoopCoordinator() {
  let sequence = 0;
  return {
    enabled: false,
    mode: 'disabled',
    ownerId: 'disabled',
    acquire(tenantId) {
      validateTenantId(tenantId);
      sequence += 1;
      return Object.freeze({
        tenantId,
        ownerId: 'disabled',
        fencingToken: sequence,
        assertValid: () => true,
        heartbeat: () => null,
        release: () => true
      });
    },
    withLease(tenantId, operation) {
      const lease = this.acquire(tenantId);
      return operation(lease);
    },
    inspect: (tenantId) => ({ status: 'disabled', tenantId, owner: null }),
    health: () => ({ status: 'disabled', enabled: false, mode: 'disabled' })
  };
}

export function createFileLeaseCoordinatorFromEnvironment(env = process.env) {
  const mode = String(env.WORKFORCE_AUDIT_COORDINATION_MODE ?? 'disabled').trim().toLowerCase();
  if (mode === 'disabled') return createNoopCoordinator();
  if (mode !== 'file-lease') throw new Error('WORKFORCE_AUDIT_COORDINATION_MODE must be disabled or file-lease.');
  return createFileLeaseCoordinator({
    directory: env.WORKFORCE_AUDIT_COORDINATION_DIR ?? '.runtime-data/workforce-audit-coordination',
    ownerId: env.WORKFORCE_AUDIT_INSTANCE_ID,
    leaseMs: env.WORKFORCE_AUDIT_LEASE_MS ? Number(env.WORKFORCE_AUDIT_LEASE_MS) : DEFAULT_LEASE_MS,
    acquireTimeoutMs: env.WORKFORCE_AUDIT_ACQUIRE_TIMEOUT_MS
      ? Number(env.WORKFORCE_AUDIT_ACQUIRE_TIMEOUT_MS)
      : DEFAULT_ACQUIRE_TIMEOUT_MS,
    retryMs: env.WORKFORCE_AUDIT_LEASE_RETRY_MS ? Number(env.WORKFORCE_AUDIT_LEASE_RETRY_MS) : DEFAULT_RETRY_MS
  });
}

function nextFencingToken(directory, tenantId) {
  const path = resolve(directory, `${hashTenantIdentifier(tenantId)}.fence`);
  let current = 0;
  if (existsSync(path)) {
    const text = readFileSync(path, 'utf8').trim();
    current = Number(text);
    if (!Number.isSafeInteger(current) || current < 0) {
      throw new CoordinationUnavailableError('The tenant fencing counter is invalid.', { tenantId, path });
    }
  }
  const next = current + 1;
  atomicWrite(path, `${next}\n`);
  return next;
}

function readOwner(path) {
  try {
    const value = JSON.parse(readFileSync(resolve(path, OWNER_FILE), 'utf8'));
    if (!value || value.version !== 1 || typeof value.ownerId !== 'string' || !Number.isSafeInteger(value.fencingToken)) return null;
    return value;
  } catch {
    return null;
  }
}

function sameLease(record, identity) {
  return Boolean(record && record.ownerId === identity.ownerId && record.fencingToken === identity.fencingToken);
}

function isExpired(record, currentTime) {
  const expiresAt = Date.parse(record?.expiresAt ?? '');
  return !Number.isFinite(expiresAt) || expiresAt <= currentTime.getTime();
}

function leaseDirectory(directory, tenantId) {
  return resolve(directory, `${hashTenantIdentifier(tenantId)}.lease`);
}

function atomicWrite(targetPath, content) {
  mkdirSync(dirname(targetPath), { recursive: true, mode: 0o700 });
  const temporaryPath = `${targetPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  let descriptor;
  try {
    descriptor = openSync(temporaryPath, 'wx', 0o600);
    writeFileSync(descriptor, content, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporaryPath, targetPath);
    fsyncDirectory(dirname(targetPath));
  } catch (error) {
    if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
    try { rmSync(temporaryPath, { force: true }); } catch {}
    throw error;
  }
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } catch {
    // Some filesystems do not expose directory fsync.
  } finally {
    if (descriptor !== undefined) { try { closeSync(descriptor); } catch {} }
  }
}

function blockingSleep(milliseconds) {
  if (milliseconds <= 0) return;
  const signal = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(signal, 0, 0, milliseconds);
}

function normaliseInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
}

function validateOwnerId(value) {
  const ownerId = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(ownerId)) throw new TypeError('ownerId must be a safe coordination identifier.');
  return ownerId;
}
