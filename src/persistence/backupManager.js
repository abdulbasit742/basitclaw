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
import { hashTenantIdentifier, PersistenceError } from './encryptedSnapshotStore.js';

const BACKUP_FORMAT = 'basitclaw-workforce-audit-backup';
const BACKUP_VERSION = 1;
const BACKUP_ID_PATTERN = /^BAK-[0-9]{14}-[a-f0-9]{8}$/;

export class BackupError extends Error {
  constructor(message, details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'BackupError';
    this.code = 'BACKUP_UNAVAILABLE';
    this.details = details;
  }
}

export class BackupNotFoundError extends Error {
  constructor(backupId) {
    super('The requested workforce-audit backup was not found.');
    this.name = 'BackupNotFoundError';
    this.code = 'BACKUP_NOT_FOUND';
    this.details = { backupId };
  }
}

export class BackupIntegrityError extends Error {
  constructor(message, details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'BackupIntegrityError';
    this.code = 'BACKUP_INTEGRITY_FAILED';
    this.details = details;
  }
}

export function createBackupManager({
  store,
  directory = resolve(store?.directory ?? '.runtime-data/workforce-audit', 'backups'),
  retention = 30,
  now = () => new Date()
} = {}) {
  if (!store || typeof store.readEncrypted !== 'function' || typeof store.inspectEncrypted !== 'function') {
    throw new TypeError('A compatible encrypted snapshot store is required.');
  }
  const absoluteDirectory = resolve(String(directory));
  const retentionLimit = normaliseRetention(retention);

  function create(tenantId, { kind = 'manual' } = {}) {
    validateTenantId(tenantId);
    validateKind(kind);
    const primary = store.readEncrypted(tenantId);
    if (!primary) {
      throw new BackupError('A durable tenant snapshot must exist before a backup can be created.', {
        tenantId,
        operation: 'create'
      });
    }

    const createdAt = now().toISOString();
    const existingBackups = list(tenantId);
    const createdOrder = Math.max(Date.parse(createdAt) * 1000, (existingBackups[0]?.createdOrder ?? 0) + 1);
    const backupId = createBackupId(createdAt);
    const tenantDirectory = tenantBackupDirectory(absoluteDirectory, tenantId);
    mkdirSync(tenantDirectory, { recursive: true, mode: 0o700 });

    const backupPath = backupEnvelopePath(tenantDirectory, backupId);
    const manifestPath = backupManifestPath(tenantDirectory, backupId);
    const checksumSha256 = sha256(primary.serialized);
    const manifest = {
      format: BACKUP_FORMAT,
      version: BACKUP_VERSION,
      backupId,
      tenantHash: hashTenantIdentifier(tenantId),
      createdAt,
      createdOrder,
      snapshotWrittenAt: primary.envelope.writtenAt,
      keyId: primary.envelope.keyId,
      checksumSha256,
      sizeBytes: Buffer.byteLength(primary.serialized, 'utf8'),
      kind
    };

    try {
      atomicWrite(backupPath, primary.serialized.trimEnd() + '\n');
      atomicWrite(manifestPath, `${JSON.stringify(manifest)}\n`);
      const prunedBackupIds = prune(tenantId);
      return { ...manifest, prunedBackupIds };
    } catch (error) {
      try { unlinkSync(backupPath); } catch {}
      try { unlinkSync(manifestPath); } catch {}
      if (error instanceof BackupError) throw error;
      throw new BackupError('The encrypted workforce-audit backup could not be created.', {
        tenantId,
        backupId,
        operation: 'create'
      }, error);
    }
  }

  function list(tenantId) {
    validateTenantId(tenantId);
    const tenantDirectory = tenantBackupDirectory(absoluteDirectory, tenantId);
    if (!existsSync(tenantDirectory)) return [];
    try {
      return readdirSync(tenantDirectory)
        .filter((name) => name.endsWith('.manifest.json'))
        .map((name) => readManifest(tenantId, resolve(tenantDirectory, name)))
        .sort((left, right) => right.createdOrder - left.createdOrder);
    } catch (error) {
      if (error instanceof BackupIntegrityError) throw error;
      throw new BackupError('Workforce-audit backup metadata could not be listed.', {
        tenantId,
        operation: 'list'
      }, error);
    }
  }

  function load(tenantId, backupId) {
    validateTenantId(tenantId);
    validateBackupId(backupId);
    const tenantDirectory = tenantBackupDirectory(absoluteDirectory, tenantId);
    const manifestPath = backupManifestPath(tenantDirectory, backupId);
    const backupPath = backupEnvelopePath(tenantDirectory, backupId);
    if (!existsSync(manifestPath) || !existsSync(backupPath)) throw new BackupNotFoundError(backupId);

    try {
      const manifest = readManifest(tenantId, manifestPath);
      const serialized = readFileSync(backupPath, 'utf8');
      const checksumSha256 = sha256(serialized);
      if (checksumSha256 !== manifest.checksumSha256) {
        throw new BackupIntegrityError('The encrypted backup checksum does not match its manifest.', {
          tenantId,
          backupId,
          expectedChecksum: manifest.checksumSha256,
          actualChecksum: checksumSha256
        });
      }
      const inspected = store.inspectEncrypted(tenantId, serialized);
      return {
        manifest,
        serialized,
        snapshot: inspected.snapshot,
        envelope: inspected.envelope
      };
    } catch (error) {
      if (error instanceof BackupNotFoundError || error instanceof BackupIntegrityError) throw error;
      if (error instanceof PersistenceError) {
        throw new BackupIntegrityError('The encrypted backup cannot be decrypted or validated.', {
          tenantId,
          backupId
        }, error);
      }
      throw new BackupError('The encrypted workforce-audit backup could not be loaded.', {
        tenantId,
        backupId,
        operation: 'load'
      }, error);
    }
  }

  function verify(tenantId, backupId) {
    const loaded = load(tenantId, backupId);
    const governanceEvents = loaded.snapshot.governanceEvents;
    return {
      valid: true,
      ...loaded.manifest,
      summary: {
        engagementCount: loaded.snapshot.state.engagements.length,
        findingCount: loaded.snapshot.state.findings.length,
        governanceEventCount: governanceEvents.length,
        governanceHeadHash: governanceEvents.at(-1)?.hash ?? null
      }
    };
  }

  function remove(tenantId, backupId) {
    validateTenantId(tenantId);
    validateBackupId(backupId);
    const tenantDirectory = tenantBackupDirectory(absoluteDirectory, tenantId);
    let removed = false;
    for (const path of [
      backupEnvelopePath(tenantDirectory, backupId),
      backupManifestPath(tenantDirectory, backupId)
    ]) {
      try {
        unlinkSync(path);
        removed = true;
      } catch (error) {
        if (error?.code !== 'ENOENT') {
          throw new BackupError('The workforce-audit backup could not be removed.', {
            tenantId,
            backupId,
            operation: 'remove'
          }, error);
        }
      }
    }
    return removed;
  }

  function health() {
    try {
      mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
      const tenantDirectoryCount = readdirSync(absoluteDirectory, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .length;
      return {
        status: 'ready',
        mode: 'encrypted-file-backup',
        directory: absoluteDirectory,
        retention: retentionLimit,
        tenantDirectoryCount
      };
    } catch (error) {
      return {
        status: 'unavailable',
        mode: 'encrypted-file-backup',
        directory: absoluteDirectory,
        retention: retentionLimit,
        tenantDirectoryCount: 0,
        error: error.message
      };
    }
  }

  function prune(tenantId) {
    const backups = list(tenantId);
    const expired = backups.slice(retentionLimit);
    const prunedBackupIds = [];
    for (const backup of expired) {
      remove(tenantId, backup.backupId);
      prunedBackupIds.push(backup.backupId);
    }
    return prunedBackupIds;
  }

  return {
    create,
    list,
    load,
    verify,
    remove,
    health,
    directory: absoluteDirectory,
    retention: retentionLimit
  };
}

export function createBackupManagerFromEnvironment(store, env = process.env) {
  const directory = env.WORKFORCE_AUDIT_BACKUP_DIR
    ?? resolve(store.directory, 'backups');
  const retention = env.WORKFORCE_AUDIT_BACKUP_RETENTION
    ? Number(env.WORKFORCE_AUDIT_BACKUP_RETENTION)
    : 30;
  return createBackupManager({ store, directory, retention });
}

function readManifest(tenantId, path) {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new BackupIntegrityError('A workforce-audit backup manifest is not valid JSON.', {
      tenantId,
      path
    }, error);
  }
  validateManifest(manifest, tenantId);
  return structuredClone(manifest);
}

function validateManifest(manifest, tenantId) {
  if (!manifest || manifest.format !== BACKUP_FORMAT || manifest.version !== BACKUP_VERSION) {
    throw new BackupIntegrityError('Unsupported workforce-audit backup manifest.', { tenantId });
  }
  validateBackupId(manifest.backupId);
  if (manifest.tenantHash !== hashTenantIdentifier(tenantId)) {
    throw new BackupIntegrityError('The backup manifest tenant binding is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  for (const field of ['createdAt', 'snapshotWrittenAt', 'keyId', 'checksumSha256', 'kind']) {
    if (typeof manifest[field] !== 'string' || manifest[field].length === 0) {
      throw new BackupIntegrityError(`The backup manifest field ${field} is missing.`, {
        tenantId,
        backupId: manifest.backupId
      });
    }
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.checksumSha256)) {
    throw new BackupIntegrityError('The backup manifest checksum is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  if (!Number.isSafeInteger(manifest.createdOrder) || manifest.createdOrder < 1) {
    throw new BackupIntegrityError('The backup manifest creation order is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  if (!Number.isInteger(manifest.sizeBytes) || manifest.sizeBytes < 1) {
    throw new BackupIntegrityError('The backup manifest size is invalid.', {
      tenantId,
      backupId: manifest.backupId
    });
  }
  validateKind(manifest.kind);
}

function createBackupId(createdAt) {
  const timestamp = createdAt.replace(/\D/g, '').slice(0, 14);
  return `BAK-${timestamp}-${randomBytes(4).toString('hex')}`;
}

function validateBackupId(value) {
  if (!BACKUP_ID_PATTERN.test(String(value ?? ''))) {
    throw new TypeError('backupId must be a safe workforce-audit backup identifier.');
  }
}

function validateKind(value) {
  if (!['manual', 'scheduled', 'safety'].includes(value)) {
    throw new TypeError('Backup kind must be manual, scheduled, or safety.');
  }
}

function normaliseRetention(value) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 365) {
    throw new TypeError('Backup retention must be an integer from 1 to 365.');
  }
  return parsed;
}

function tenantBackupDirectory(directory, tenantId) {
  return resolve(directory, hashTenantIdentifier(tenantId));
}

function backupEnvelopePath(directory, backupId) {
  return resolve(directory, `${backupId}.snapshot.enc`);
}

function backupManifestPath(directory, backupId) {
  return resolve(directory, `${backupId}.manifest.json`);
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
    // Some platforms do not support directory fsync.
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) {
    throw new TypeError('tenantId must be a safe identifier.');
  }
}
