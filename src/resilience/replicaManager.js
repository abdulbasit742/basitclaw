import { createHash, randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { hashTenantIdentifier, PersistenceError } from '../persistence/encryptedSnapshotStore.js';

const REPLICA_FORMAT = 'basitclaw-workforce-audit-replica';
const REPLICA_VERSION = 1;
const BACKUP_ID_PATTERN = /^BAK-[0-9]{14}-[a-f0-9]{8}$/;

export class ReplicaError extends Error {
  constructor(message, details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'ReplicaError';
    this.code = 'REPLICA_UNAVAILABLE';
    this.details = details;
  }
}

export class ReplicaNotFoundError extends Error {
  constructor(backupId) {
    super('The requested workforce-audit replica was not found.');
    this.name = 'ReplicaNotFoundError';
    this.code = 'REPLICA_NOT_FOUND';
    this.details = { backupId };
  }
}

export class ReplicaIntegrityError extends Error {
  constructor(message, details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'ReplicaIntegrityError';
    this.code = 'REPLICA_INTEGRITY_FAILED';
    this.details = details;
  }
}

export function createReplicaManager({
  store,
  backupManager,
  directory,
  retention = 90,
  required = false,
  maxLagMinutes = 2880,
  now = () => new Date()
} = {}) {
  if (!store || typeof store.inspectEncrypted !== 'function') {
    throw new TypeError('A compatible encrypted snapshot store is required for replication.');
  }
  if (!backupManager || typeof backupManager.load !== 'function') {
    throw new TypeError('A compatible backup manager is required for replication.');
  }
  const absoluteDirectory = resolve(String(directory ?? '.runtime-data/workforce-audit-replicas'));
  const retentionLimit = normaliseInteger(retention, 'Replica retention', 1, 730);
  const lagLimit = normaliseInteger(maxLagMinutes, 'Replica maximum lag', 1, 525600);
  const isRequired = Boolean(required);

  function replicate(tenantId, backupId) {
    validateTenantId(tenantId);
    validateBackupId(backupId);
    const source = backupManager.load(tenantId, backupId);
    const checksumSha256 = sha256(source.serialized);
    const replicas = list(tenantId);
    const existing = replicas.find((item) => item.backupId === backupId);
    if (existing) {
      const verified = verify(tenantId, backupId);
      if (verified.checksumSha256 !== checksumSha256) {
        throw new ReplicaIntegrityError('An existing replica conflicts with the source recovery point.', {
          tenantId,
          backupId,
          sourceChecksum: checksumSha256,
          replicaChecksum: verified.checksumSha256
        });
      }
      return { ...existing, prunedReplicaIds: [], idempotent: true };
    }
    const replicatedAt = now().toISOString();
    const replicatedOrder = Math.max(Date.parse(replicatedAt) * 1000, (replicas[0]?.replicatedOrder ?? 0) + 1);
    const manifest = {
      format: REPLICA_FORMAT,
      version: REPLICA_VERSION,
      backupId,
      tenantHash: hashTenantIdentifier(tenantId),
      sourceCreatedAt: source.manifest.createdAt,
      replicatedAt,
      replicatedOrder,
      keyId: source.envelope.keyId,
      checksumSha256,
      sizeBytes: Buffer.byteLength(source.serialized, 'utf8'),
      kind: source.manifest.kind
    };
    const targetDirectory = tenantReplicaDirectory(absoluteDirectory, tenantId);
    const envelopePath = replicaEnvelopePath(targetDirectory, backupId);
    const manifestPath = replicaManifestPath(targetDirectory, backupId);
    try {
      atomicWrite(envelopePath, `${source.serialized.trim()}\n`);
      atomicWrite(manifestPath, `${JSON.stringify(manifest)}\n`);
      const prunedReplicaIds = prune(tenantId);
      return { ...manifest, prunedReplicaIds };
    } catch (error) {
      try { unlinkSync(envelopePath); } catch {}
      try { unlinkSync(manifestPath); } catch {}
      if (error instanceof ReplicaError) throw error;
      throw new ReplicaError('The workforce-audit replica could not be written.', {
        tenantId,
        backupId,
        operation: 'replicate'
      }, error);
    }
  }

  function list(tenantId) {
    validateTenantId(tenantId);
    const targetDirectory = tenantReplicaDirectory(absoluteDirectory, tenantId);
    if (!existsSync(targetDirectory)) return [];
    try {
      return readdirSync(targetDirectory)
        .filter((name) => name.endsWith('.replica.json'))
        .map((name) => readManifest(tenantId, resolve(targetDirectory, name)))
        .sort((left, right) => right.replicatedOrder - left.replicatedOrder);
    } catch (error) {
      if (error instanceof ReplicaIntegrityError) throw error;
      throw new ReplicaError('Workforce-audit replica metadata could not be listed.', {
        tenantId,
        operation: 'list'
      }, error);
    }
  }

  function verify(tenantId, backupId) {
    validateTenantId(tenantId);
    validateBackupId(backupId);
    const targetDirectory = tenantReplicaDirectory(absoluteDirectory, tenantId);
    const envelopePath = replicaEnvelopePath(targetDirectory, backupId);
    const manifestPath = replicaManifestPath(targetDirectory, backupId);
    if (!existsSync(envelopePath) || !existsSync(manifestPath)) throw new ReplicaNotFoundError(backupId);
    try {
      const manifest = readManifest(tenantId, manifestPath);
      const serialized = readFileSync(envelopePath, 'utf8');
      const checksumSha256 = sha256(serialized);
      if (checksumSha256 !== manifest.checksumSha256) {
        throw new ReplicaIntegrityError('The encrypted replica checksum does not match its manifest.', {
          tenantId,
          backupId,
          expectedChecksum: manifest.checksumSha256,
          actualChecksum: checksumSha256
        });
      }
      if (Buffer.byteLength(serialized, 'utf8') !== manifest.sizeBytes) {
        throw new ReplicaIntegrityError('The encrypted replica size does not match its manifest.', {
          tenantId,
          backupId
        });
      }
      const inspected = store.inspectEncrypted(tenantId, serialized);
      const governanceEvents = inspected.snapshot.governanceEvents;
      return {
        valid: true,
        ...manifest,
        summary: {
          engagementCount: inspected.snapshot.state.engagements.length,
          findingCount: inspected.snapshot.state.findings.length,
          governanceEventCount: governanceEvents.length,
          governanceHeadHash: governanceEvents.at(-1)?.hash ?? null
        }
      };
    } catch (error) {
      if (error instanceof ReplicaNotFoundError || error instanceof ReplicaIntegrityError) throw error;
      if (error instanceof PersistenceError) {
        throw new ReplicaIntegrityError('The encrypted replica cannot be decrypted or tenant-validated.', {
          tenantId,
          backupId
        }, error);
      }
      throw new ReplicaError('The workforce-audit replica could not be verified.', {
        tenantId,
        backupId,
        operation: 'verify'
      }, error);
    }
  }

  function remove(tenantId, backupId) {
    validateTenantId(tenantId);
    validateBackupId(backupId);
    const targetDirectory = tenantReplicaDirectory(absoluteDirectory, tenantId);
    let removed = false;
    for (const path of [
      replicaEnvelopePath(targetDirectory, backupId),
      replicaManifestPath(targetDirectory, backupId)
    ]) {
      try {
        unlinkSync(path);
        removed = true;
      } catch (error) {
        if (error?.code !== 'ENOENT') {
          throw new ReplicaError('The workforce-audit replica could not be removed.', {
            tenantId,
            backupId,
            operation: 'remove'
          }, error);
        }
      }
    }
    return removed;
  }

  function tenantHealth(tenantId) {
    try {
      const latest = list(tenantId)[0] ?? null;
      if (!latest) {
        return {
          status: isRequired ? 'missing' : 'empty',
          required: isRequired,
          maxLagMinutes: lagLimit,
          latestReplica: null,
          lagMinutes: null
        };
      }
      const lagMinutes = Math.max(0, Math.floor((now().getTime() - new Date(latest.replicatedAt).getTime()) / 60000));
      return {
        status: lagMinutes > lagLimit ? 'stale' : 'ready',
        required: isRequired,
        maxLagMinutes: lagLimit,
        latestReplica: latest,
        lagMinutes
      };
    } catch (error) {
      return {
        status: 'unavailable',
        required: isRequired,
        maxLagMinutes: lagLimit,
        latestReplica: null,
        lagMinutes: null,
        error: error.message
      };
    }
  }

  function health() {
    try {
      mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(absoluteDirectory, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .length;
      return {
        status: 'ready',
        enabled: true,
        required: isRequired,
        mode: 'encrypted-file-replica',
        directory: absoluteDirectory,
        retention: retentionLimit,
        maxLagMinutes: lagLimit,
        tenantDirectoryCount
      };
    } catch (error) {
      return {
        status: 'unavailable',
        enabled: true,
        required: isRequired,
        mode: 'encrypted-file-replica',
        directory: absoluteDirectory,
        retention: retentionLimit,
        maxLagMinutes: lagLimit,
        tenantDirectoryCount: 0,
        error: error.message
      };
    }
  }

  function prune(tenantId) {
    const expired = list(tenantId).slice(retentionLimit);
    const prunedReplicaIds = [];
    for (const replica of expired) {
      remove(tenantId, replica.backupId);
      prunedReplicaIds.push(replica.backupId);
    }
    return prunedReplicaIds;
  }

  return {
    replicate,
    list,
    verify,
    remove,
    tenantHealth,
    health,
    enabled: true,
    required: isRequired,
    directory: absoluteDirectory,
    retention: retentionLimit,
    maxLagMinutes: lagLimit
  };
}

export function createReplicaManagerFromEnvironment(store, backupManager, env = process.env) {
  const required = parseBoolean(env.WORKFORCE_AUDIT_REPLICATION_REQUIRED, false);
  const directory = env.WORKFORCE_AUDIT_REPLICA_DIR;
  if (!directory) {
    if (required) throw new Error('WORKFORCE_AUDIT_REPLICA_DIR is required when replication is required.');
    return createDisabledReplicaManager();
  }
  return createReplicaManager({
    store,
    backupManager,
    directory,
    retention: env.WORKFORCE_AUDIT_REPLICA_RETENTION ? Number(env.WORKFORCE_AUDIT_REPLICA_RETENTION) : 90,
    required,
    maxLagMinutes: env.WORKFORCE_AUDIT_REPLICA_MAX_LAG_MINUTES
      ? Number(env.WORKFORCE_AUDIT_REPLICA_MAX_LAG_MINUTES)
      : 2880
  });
}

export function createDisabledReplicaManager() {
  const unavailable = () => {
    throw new ReplicaError('Encrypted replica operations are disabled.', { operation: 'replica' });
  };
  return {
    replicate: unavailable,
    list: () => [],
    verify: unavailable,
    remove: () => false,
    tenantHealth: () => ({
      status: 'disabled',
      required: false,
      maxLagMinutes: null,
      latestReplica: null,
      lagMinutes: null
    }),
    health: () => ({
      status: 'disabled',
      enabled: false,
      required: false,
      mode: 'encrypted-file-replica',
      retention: 0,
      maxLagMinutes: null,
      tenantDirectoryCount: 0
    }),
    enabled: false,
    required: false,
    directory: null,
    retention: 0,
    maxLagMinutes: null
  };
}

function readManifest(tenantId, path) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new ReplicaIntegrityError('A workforce-audit replica manifest is not valid JSON.', {
      tenantId,
      path
    }, error);
  }
  validateManifest(manifest, tenantId);
  return structuredClone(manifest);
}

function validateManifest(manifest, tenantId) {
  if (!manifest || manifest.format !== REPLICA_FORMAT || manifest.version !== REPLICA_VERSION) {
    throw new ReplicaIntegrityError('Unsupported workforce-audit replica manifest.', { tenantId });
  }
  validateBackupId(manifest.backupId);
  if (manifest.tenantHash !== hashTenantIdentifier(tenantId)) {
    throw new ReplicaIntegrityError('The replica manifest tenant binding is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  for (const field of ['sourceCreatedAt', 'replicatedAt', 'keyId', 'checksumSha256', 'kind']) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) {
      throw new ReplicaIntegrityError(`The replica manifest field ${field} is missing.`, {
        tenantId,
        backupId: manifest.backupId
      });
    }
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.checksumSha256)) {
    throw new ReplicaIntegrityError('The replica manifest checksum is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  if (!Number.isSafeInteger(manifest.replicatedOrder) || manifest.replicatedOrder < 1) {
    throw new ReplicaIntegrityError('The replica manifest order is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  if (!Number.isInteger(manifest.sizeBytes) || manifest.sizeBytes < 1) {
    throw new ReplicaIntegrityError('The replica manifest size is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
}

function parseBoolean(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  if (value === true || value === 'true' || value === '1') return true;
  if (value === false || value === 'false' || value === '0') return false;
  throw new TypeError('Replication boolean configuration must be true or false.');
}

function normaliseInteger(value, label, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new TypeError(`${label} must be an integer from ${minimum} to ${maximum}.`);
  }
  return parsed;
}

function validateBackupId(value) {
  if (!BACKUP_ID_PATTERN.test(String(value ?? ''))) throw new TypeError('backupId must be a safe workforce-audit backup identifier.');
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
}

function tenantReplicaDirectory(directory, tenantId) {
  return resolve(directory, hashTenantIdentifier(tenantId));
}

function replicaEnvelopePath(directory, backupId) {
  return resolve(directory, `${backupId}.snapshot.enc`);
}

function replicaManifestPath(directory, backupId) {
  return resolve(directory, `${backupId}.replica.json`);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
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
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
    try { unlinkSync(temporaryPath); } catch {}
    throw error;
  }
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } catch {
    // Directory fsync is not supported on every platform.
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
}
