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
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import { hashTenantIdentifier, PersistenceError } from '../persistence/encryptedSnapshotStore.js';

const FORMAT = 'basitclaw-workforce-audit-fenced-snapshot';
const VERSION = 1;
const TOKEN_WIDTH = 20;

export class FencingRejectedError extends PersistenceError {
  constructor(message = 'The snapshot write was rejected by the fencing boundary.', details = {}) {
    super(message, details);
    this.name = 'FencingRejectedError';
    this.code = 'PERSISTENCE_FENCE_REJECTED';
  }
}

export function createFencedSnapshotStore({
  store,
  directory = resolve(store?.directory ?? '.runtime-data/workforce-audit', 'fenced'),
  retainedVersions = 5
} = {}) {
  if (!store || typeof store.serialize !== 'function' || typeof store.inspectEncrypted !== 'function') {
    throw new TypeError('A serialisable encrypted snapshot store is required.');
  }
  const absoluteDirectory = resolve(String(directory));
  const keep = normaliseInteger(retainedVersions, 'retainedVersions', 2, 100);

  function load(tenantId) {
    return readEncrypted(tenantId)?.snapshot ?? null;
  }

  function readEncrypted(tenantId) {
    validateTenantId(tenantId);
    const versions = listVersions(tenantId);
    if (versions.length === 0) return store.readEncrypted(tenantId);
    const latest = versions[0];
    try {
      const packageText = readFileSync(latest.path, 'utf8');
      const fenced = parsePackage(packageText, tenantId, latest.fencingToken);
      const inspected = store.inspectEncrypted(tenantId, fenced.serialized);
      return {
        ...inspected,
        serialized: fenced.serialized,
        path: latest.path,
        fencingToken: latest.fencingToken,
        packageChecksumSha256: fenced.checksumSha256
      };
    } catch (error) {
      if (error instanceof PersistenceError) throw error;
      throw new PersistenceError('Fenced encrypted workforce-audit state could not be loaded.', {
        tenantId,
        fencingToken: latest.fencingToken,
        operation: 'load-fenced'
      }, error);
    }
  }

  function save(tenantId, snapshot, { fencingToken } = {}) {
    validateTenantId(tenantId);
    const token = validateFencingToken(fencingToken);
    const latest = listVersions(tenantId)[0] ?? null;
    if (latest && token < latest.fencingToken) {
      throw new FencingRejectedError(undefined, {
        tenantId,
        suppliedFencingToken: token,
        latestFencingToken: latest.fencingToken
      });
    }

    const serialized = store.serialize(tenantId, snapshot);
    const packageRecord = createPackage(tenantId, token, serialized);
    const targetPath = versionPath(absoluteDirectory, tenantId, token);
    atomicWrite(targetPath, `${JSON.stringify(packageRecord)}\n`);
    pruneVersions(tenantId);
    const envelope = JSON.parse(serialized);
    return {
      tenantId,
      keyId: envelope.keyId,
      writtenAt: envelope.writtenAt,
      path: targetPath,
      fencingToken: token
    };
  }

  function writeEncrypted(tenantId, serialized, { fencingToken } = {}) {
    const inspected = store.inspectEncrypted(tenantId, serialized);
    const result = save(tenantId, inspected.snapshot, { fencingToken });
    return { ...result, snapshot: inspected.snapshot };
  }

  function inspectEncrypted(tenantId, serialized) {
    return store.inspectEncrypted(tenantId, serialized);
  }

  function serialize(tenantId, snapshot) {
    return store.serialize(tenantId, snapshot);
  }

  function latestFencingToken(tenantId) {
    validateTenantId(tenantId);
    return listVersions(tenantId)[0]?.fencingToken ?? 0;
  }

  function health() {
    try {
      mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
      const tenantDirectories = readdirSync(absoluteDirectory, { withFileTypes: true })
        .filter((entry) => entry.isDirectory() && /^[a-f0-9]{64}$/.test(entry.name));
      return {
        status: 'ready',
        mode: 'encrypted-file-fenced',
        coordinated: true,
        directory: absoluteDirectory,
        primaryKeyId: store.primaryKeyId,
        persistedTenantCount: tenantDirectories.length,
        retainedVersions: keep
      };
    } catch (error) {
      return {
        status: 'unavailable',
        mode: 'encrypted-file-fenced',
        coordinated: true,
        directory: absoluteDirectory,
        primaryKeyId: store.primaryKeyId,
        persistedTenantCount: 0,
        retainedVersions: keep,
        error: error.message
      };
    }
  }

  function listVersions(tenantId) {
    const tenantDirectory = resolve(absoluteDirectory, hashTenantIdentifier(tenantId));
    if (!existsSync(tenantDirectory)) return [];
    try {
      return readdirSync(tenantDirectory)
        .map((name) => {
          const match = name.match(/^([0-9]{20})\.snapshot\.fenced$/);
          if (!match) return null;
          return {
            fencingToken: Number(match[1]),
            path: resolve(tenantDirectory, name)
          };
        })
        .filter(Boolean)
        .sort((left, right) => right.fencingToken - left.fencingToken);
    } catch (error) {
      throw new PersistenceError('Fenced snapshot versions could not be listed.', { tenantId, operation: 'list-fenced' }, error);
    }
  }

  function pruneVersions(tenantId) {
    const versions = listVersions(tenantId).slice(keep);
    for (const version of versions) {
      try { rmSync(version.path, { force: true }); } catch {}
    }
  }

  return {
    load,
    save,
    serialize,
    readEncrypted,
    inspectEncrypted,
    writeEncrypted,
    latestFencingToken,
    listVersions,
    health,
    directory: absoluteDirectory,
    primaryKeyId: store.primaryKeyId,
    coordinated: true
  };
}

export function bindFencingToken(store, fencingToken) {
  const token = validateFencingToken(fencingToken);
  return {
    ...store,
    save: (tenantId, snapshot) => store.save(tenantId, snapshot, { fencingToken: token }),
    writeEncrypted: (tenantId, serialized) => store.writeEncrypted(tenantId, serialized, { fencingToken: token }),
    fencingToken: token
  };
}

function createPackage(tenantId, fencingToken, serialized) {
  return {
    format: FORMAT,
    version: VERSION,
    tenantHash: hashTenantIdentifier(tenantId),
    fencingToken,
    checksumSha256: sha256(serialized),
    serialized
  };
}

function parsePackage(text, tenantId, expectedToken) {
  let value;
  try { value = JSON.parse(text); } catch (error) {
    throw new PersistenceError('A fenced snapshot package is not valid JSON.', { tenantId, expectedToken }, error);
  }
  if (!value || value.format !== FORMAT || value.version !== VERSION) {
    throw new PersistenceError('Unsupported fenced snapshot package.', { tenantId, expectedToken });
  }
  if (value.tenantHash !== hashTenantIdentifier(tenantId) || value.fencingToken !== expectedToken) {
    throw new PersistenceError('The fenced snapshot tenant or token binding is invalid.', { tenantId, expectedToken });
  }
  if (typeof value.serialized !== 'string' || sha256(value.serialized) !== value.checksumSha256) {
    throw new PersistenceError('The fenced snapshot checksum is invalid.', { tenantId, expectedToken });
  }
  return value;
}

function versionPath(directory, tenantId, token) {
  return resolve(directory, hashTenantIdentifier(tenantId), `${String(token).padStart(TOKEN_WIDTH, '0')}.snapshot.fenced`);
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
    throw new PersistenceError('Fenced encrypted workforce-audit state could not be written.', { operation: 'write-fenced' }, error);
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validateFencingToken(value) {
  const token = Number(value);
  if (!Number.isSafeInteger(token) || token < 1) throw new FencingRejectedError('A positive safe-integer fencing token is required.', { suppliedFencingToken: value });
  return token;
}

function normaliseInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  return parsed;
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
}
