import { createHash, randomUUID } from 'node:crypto';
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
import { dirname, resolve } from 'node:path';
import { createFileMutex } from './fileMutex.js';

export function createSecurityAlertOutbox({
  directory,
  now = () => new Date(),
  mutex = null,
  inflightLeaseMs = 60_000,
  deliveredRetention = 10_000,
  deadLetterRetention = 2_000,
  lockLeaseMs = 10_000,
  lockAcquireTimeoutMs = 2_000,
  lockRetryMs = 10
} = {}) {
  if (!String(directory ?? '').trim()) throw new TypeError('A security alert outbox directory is required.');
  const root = resolve(String(directory));
  const pendingDir = resolve(root, 'pending');
  const inflightDir = resolve(root, 'inflight');
  const deliveredDir = resolve(root, 'delivered');
  const deadDir = resolve(root, 'dead-letter');
  const safeInflightLeaseMs = integer(inflightLeaseMs, 'inflightLeaseMs', 1_000, 86_400_000);
  const safeDeliveredRetention = integer(deliveredRetention, 'deliveredRetention', 100, 1_000_000);
  const safeDeadRetention = integer(deadLetterRetention, 'deadLetterRetention', 1, 100_000);
  for (const directoryPath of [root, pendingDir, inflightDir, deliveredDir, deadDir]) ensureDirectory(directoryPath);
  const lock = mutex ?? createFileMutex({
    directory: resolve(root, 'locks'),
    leaseMs: lockLeaseMs,
    acquireTimeoutMs: lockAcquireTimeoutMs,
    retryMs: lockRetryMs,
    now
  });

  function enqueue(event) {
    return lock.withLock('security-alert-outbox', () => {
      recoverStaleLocked();
      const deliveryId = deliveryIdFor(event);
      const filename = `${deliveryId}.json`;
      for (const directoryPath of [pendingDir, inflightDir, deliveredDir, deadDir]) {
        const existing = resolve(directoryPath, filename);
        if (existsSync(existing)) return { enqueued: false, duplicate: true, deliveryId, state: stateName(directoryPath) };
      }
      const current = now().toISOString();
      const item = {
        version: 1,
        deliveryId,
        state: 'pending',
        createdAt: current,
        updatedAt: current,
        attempts: 0,
        nextAttemptAt: current,
        lastAttemptAt: null,
        lastStatus: null,
        lastError: null,
        event: structuredClone(event)
      };
      writeJsonAtomic(resolve(pendingDir, filename), item);
      return { enqueued: true, duplicate: false, deliveryId, state: 'pending' };
    });
  }

  function claimDue({ limit = 25 } = {}) {
    const safeLimit = integer(limit, 'limit', 1, 500);
    return lock.withLock('security-alert-outbox', () => {
      recoverStaleLocked();
      const currentMs = now().getTime();
      const claimed = [];
      for (const filename of jsonNames(pendingDir)) {
        if (claimed.length >= safeLimit) break;
        const source = resolve(pendingDir, filename);
        const item = readJson(source);
        if (new Date(item.nextAttemptAt).getTime() > currentMs) continue;
        const claimToken = randomUUID();
        const claimedAt = now().toISOString();
        const inflight = {
          ...item,
          state: 'inflight',
          updatedAt: claimedAt,
          claimedAt,
          claimToken,
          claimExpiresAt: new Date(now().getTime() + safeInflightLeaseMs).toISOString()
        };
        writeJsonAtomic(source, inflight);
        const target = resolve(inflightDir, filename);
        renameSync(source, target);
        syncDirectory(pendingDir);
        syncDirectory(inflightDir);
        claimed.push(structuredClone(inflight));
      }
      return claimed;
    });
  }

  function complete(deliveryId, claimToken, result = {}) {
    return lock.withLock('security-alert-outbox', () => {
      const source = resolve(inflightDir, `${safeDeliveryId(deliveryId)}.json`);
      const item = readClaim(source, claimToken);
      const completedAt = now().toISOString();
      const receipt = {
        version: 1,
        deliveryId: item.deliveryId,
        state: 'delivered',
        createdAt: item.createdAt,
        deliveredAt: completedAt,
        attempts: item.attempts + 1,
        responseStatus: result.status ?? null,
        responseId: safeResponseId(result.responseId),
        eventId: item.event?.id ?? null,
        eventHash: item.event?.hash ?? null
      };
      writeJsonAtomic(source, receipt);
      renameSync(source, resolve(deliveredDir, `${item.deliveryId}.json`));
      syncDirectory(inflightDir);
      syncDirectory(deliveredDir);
      pruneDirectory(deliveredDir, safeDeliveredRetention);
      return structuredClone(receipt);
    });
  }

  function retry(deliveryId, claimToken, { nextAttemptAt, status = null, error = null } = {}) {
    return lock.withLock('security-alert-outbox', () => {
      const source = resolve(inflightDir, `${safeDeliveryId(deliveryId)}.json`);
      const item = readClaim(source, claimToken);
      const attemptAt = now().toISOString();
      const updated = {
        ...item,
        state: 'pending',
        updatedAt: attemptAt,
        attempts: item.attempts + 1,
        nextAttemptAt: new Date(nextAttemptAt).toISOString(),
        lastAttemptAt: attemptAt,
        lastStatus: status,
        lastError: safeError(error)
      };
      delete updated.claimedAt;
      delete updated.claimToken;
      delete updated.claimExpiresAt;
      writeJsonAtomic(source, updated);
      renameSync(source, resolve(pendingDir, `${item.deliveryId}.json`));
      syncDirectory(inflightDir);
      syncDirectory(pendingDir);
      return structuredClone(updated);
    });
  }

  function deadLetter(deliveryId, claimToken, { status = null, error = null, reason = 'delivery_failed' } = {}) {
    return lock.withLock('security-alert-outbox', () => {
      const source = resolve(inflightDir, `${safeDeliveryId(deliveryId)}.json`);
      const item = readClaim(source, claimToken);
      const attemptAt = now().toISOString();
      const dead = {
        ...item,
        state: 'dead-letter',
        updatedAt: attemptAt,
        deadLetteredAt: attemptAt,
        attempts: item.attempts + 1,
        lastAttemptAt: attemptAt,
        lastStatus: status,
        lastError: safeError(error),
        deadLetterReason: String(reason).slice(0, 128)
      };
      delete dead.claimedAt;
      delete dead.claimToken;
      delete dead.claimExpiresAt;
      writeJsonAtomic(source, dead);
      renameSync(source, resolve(deadDir, `${item.deliveryId}.json`));
      syncDirectory(inflightDir);
      syncDirectory(deadDir);
      pruneDirectory(deadDir, safeDeadRetention);
      return structuredClone(dead);
    });
  }

  function listDeadLetters({ limit = 100 } = {}) {
    const safeLimit = integer(limit, 'limit', 1, 500);
    return lock.withLock('security-alert-outbox', () => jsonNames(deadDir)
      .slice(-safeLimit)
      .reverse()
      .map((name) => readJson(resolve(deadDir, name))));
  }

  function requeue(deliveryId) {
    return lock.withLock('security-alert-outbox', () => {
      const safeId = safeDeliveryId(deliveryId);
      const source = resolve(deadDir, `${safeId}.json`);
      const item = readJson(source);
      const current = now().toISOString();
      const pending = {
        ...item,
        state: 'pending',
        updatedAt: current,
        nextAttemptAt: current,
        lastError: null
      };
      delete pending.deadLetteredAt;
      delete pending.deadLetterReason;
      writeJsonAtomic(source, pending);
      renameSync(source, resolve(pendingDir, `${safeId}.json`));
      syncDirectory(deadDir);
      syncDirectory(pendingDir);
      return structuredClone(pending);
    });
  }

  function health() {
    try {
      return lock.withLock('security-alert-outbox', () => {
        recoverStaleLocked();
        const pending = jsonNames(pendingDir).map((name) => readJson(resolve(pendingDir, name)));
        const inflight = jsonNames(inflightDir);
        const dead = jsonNames(deadDir);
        return {
          status: dead.length > 0 ? 'degraded' : 'ready',
          mode: 'shared-file-durable-outbox',
          durable: true,
          distributed: true,
          directory: root,
          pending: pending.length,
          inflight: inflight.length,
          deadLetters: dead.length,
          oldestPendingAt: pending.sort((a, b) => a.createdAt.localeCompare(b.createdAt))[0]?.createdAt ?? null,
          mutex: lock.health()
        };
      });
    } catch (error) {
      return {
        status: 'unavailable',
        mode: 'shared-file-durable-outbox',
        durable: true,
        distributed: true,
        directory: root,
        error: error.message
      };
    }
  }

  function recoverStaleLocked() {
    const currentMs = now().getTime();
    for (const filename of jsonNames(inflightDir)) {
      const source = resolve(inflightDir, filename);
      let item;
      try { item = readJson(source); } catch { continue; }
      if (new Date(item.claimExpiresAt ?? 0).getTime() > currentMs) continue;
      const recovered = {
        ...item,
        state: 'pending',
        updatedAt: now().toISOString(),
        nextAttemptAt: now().toISOString(),
        lastError: 'Recovered after an expired in-flight claim.'
      };
      delete recovered.claimedAt;
      delete recovered.claimToken;
      delete recovered.claimExpiresAt;
      writeJsonAtomic(source, recovered);
      renameSync(source, resolve(pendingDir, filename));
    }
    syncDirectory(inflightDir);
    syncDirectory(pendingDir);
  }

  return {
    enqueue,
    claimDue,
    complete,
    retry,
    deadLetter,
    listDeadLetters,
    requeue,
    health,
    directory: root
  };
}

function deliveryIdFor(event) {
  const stable = event?.hash || `${event?.id ?? ''}:${event?.occurredAt ?? ''}:${JSON.stringify(event ?? {})}`;
  return `ALERT-${createHash('sha256').update(String(stable)).digest('hex').slice(0, 32)}`;
}

function safeDeliveryId(value) {
  const id = String(value ?? '');
  if (!/^ALERT-[a-f0-9]{32}$/.test(id)) throw new TypeError('Security alert delivery ID is invalid.');
  return id;
}

function readClaim(path, token) {
  const item = readJson(path);
  if (item.state !== 'inflight' || item.claimToken !== token) throw new Error('Security alert delivery claim is no longer owned.');
  return item;
}

function safeResponseId(value) {
  if (value === undefined || value === null || value === '') return null;
  return String(value).replace(/[^a-zA-Z0-9._:-]/g, '').slice(0, 128) || null;
}

function safeError(value) {
  if (value === undefined || value === null) return null;
  return String(value).slice(0, 500);
}

function stateName(directoryPath) {
  return directoryPath.endsWith('pending') ? 'pending'
    : directoryPath.endsWith('inflight') ? 'inflight'
      : directoryPath.endsWith('delivered') ? 'delivered' : 'dead-letter';
}

function ensureDirectory(directory) {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
}

function jsonNames(directory) {
  return readdirSync(directory).filter((name) => /^ALERT-[a-f0-9]{32}\.json$/.test(name)).sort();
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJsonAtomic(path, value) {
  ensureDirectory(dirname(path));
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  writeFileSync(temporary, `${JSON.stringify(value)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  const fd = openSync(temporary, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, path);
  syncDirectory(dirname(path));
}

function syncDirectory(directory) {
  try {
    const fd = openSync(directory, 'r');
    try { fsyncSync(fd); } finally { closeSync(fd); }
  } catch {
    // Some filesystems do not permit directory fsync; atomic rename still protects file visibility.
  }
}

function pruneDirectory(directory, retain) {
  const names = jsonNames(directory);
  for (const name of names.slice(0, Math.max(0, names.length - retain))) rmSync(resolve(directory, name), { force: true });
  syncDirectory(directory);
}

function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}
