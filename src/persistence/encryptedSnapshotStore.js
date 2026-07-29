import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes
} from 'node:crypto';
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

const FORMAT = 'basitclaw-workforce-audit-snapshot';
const ENVELOPE_VERSION = 1;
const ALGORITHM = 'aes-256-gcm';
const MAX_ENCRYPTED_BYTES = 64 * 1024 * 1024;

export class PersistenceError extends Error {
  constructor(message, details = {}, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = 'PersistenceError';
    this.code = 'PERSISTENCE_UNAVAILABLE';
    this.details = details;
  }
}

export function createEncryptedSnapshotStore({
  directory,
  keys,
  primaryKeyId,
  now = () => new Date()
}) {
  const absoluteDirectory = resolve(String(directory ?? '.runtime-data/workforce-audit'));
  const keyring = normaliseKeyring(keys);
  if (!keyring.has(primaryKeyId)) throw new TypeError('primaryKeyId must identify a configured encryption key.');

  function load(tenantId) {
    return readEncrypted(tenantId)?.snapshot ?? null;
  }

  function readEncrypted(tenantId) {
    validateTenantId(tenantId);
    const path = tenantPath(absoluteDirectory, tenantId);
    if (!existsSync(path)) return null;
    try {
      const serialized = readFileSync(path, 'utf8');
      return { ...inspectEncrypted(tenantId, serialized), serialized, path };
    } catch (error) {
      if (error instanceof PersistenceError) throw error;
      throw new PersistenceError('Encrypted workforce-audit state could not be loaded.', {
        tenantId,
        operation: 'load'
      }, error);
    }
  }

  function inspectEncrypted(tenantId, serialized) {
    validateTenantId(tenantId);
    try {
      const text = normaliseSerializedEnvelope(serialized);
      const envelope = JSON.parse(text);
      validateEnvelope(envelope, tenantId);
      const snapshot = decryptEnvelope(envelope, tenantId, keyring);
      return {
        envelope: structuredClone(envelope),
        snapshot: structuredClone(snapshot)
      };
    } catch (error) {
      if (error instanceof PersistenceError) throw error;
      throw new PersistenceError('Encrypted workforce-audit state could not be inspected.', {
        tenantId,
        operation: 'inspect'
      }, error);
    }
  }

  function save(tenantId, snapshot) {
    validateTenantId(tenantId);
    validateSnapshot(snapshot, tenantId);
    mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
    const iv = randomBytes(12);
    const key = keyring.get(primaryKeyId);
    const envelopeBase = {
      format: FORMAT,
      version: ENVELOPE_VERSION,
      algorithm: ALGORITHM,
      keyId: primaryKeyId,
      tenantHash: hashTenantIdentifier(tenantId),
      writtenAt: now().toISOString(),
      iv: iv.toString('base64')
    };
    const cipher = createCipheriv(ALGORITHM, key, iv);
    cipher.setAAD(Buffer.from(associatedData(envelopeBase)));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(snapshot), 'utf8'),
      cipher.final()
    ]);
    const envelope = {
      ...envelopeBase,
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64')
    };
    const targetPath = tenantPath(absoluteDirectory, tenantId);
    atomicWrite(targetPath, `${JSON.stringify(envelope)}\n`, tenantId, 'save');
    return { tenantId, keyId: primaryKeyId, writtenAt: envelope.writtenAt, path: targetPath };
  }

  function writeEncrypted(tenantId, serialized) {
    validateTenantId(tenantId);
    const inspected = inspectEncrypted(tenantId, serialized);
    mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
    const targetPath = tenantPath(absoluteDirectory, tenantId);
    const text = `${normaliseSerializedEnvelope(serialized).trim()}\n`;
    atomicWrite(targetPath, text, tenantId, 'restore');
    return {
      tenantId,
      keyId: inspected.envelope.keyId,
      writtenAt: inspected.envelope.writtenAt,
      path: targetPath,
      snapshot: inspected.snapshot
    };
  }

  function health() {
    try {
      mkdirSync(absoluteDirectory, { recursive: true, mode: 0o700 });
      const persistedTenantCount = readdirSync(absoluteDirectory).filter((name) => name.endsWith('.snapshot.enc')).length;
      return {
        status: 'ready',
        mode: 'encrypted-file',
        directory: absoluteDirectory,
        primaryKeyId,
        configuredKeyIds: [...keyring.keys()],
        persistedTenantCount
      };
    } catch (error) {
      return {
        status: 'unavailable',
        mode: 'encrypted-file',
        directory: absoluteDirectory,
        primaryKeyId,
        configuredKeyIds: [...keyring.keys()],
        persistedTenantCount: 0,
        error: error.message
      };
    }
  }

  return {
    load,
    save,
    readEncrypted,
    inspectEncrypted,
    writeEncrypted,
    health,
    directory: absoluteDirectory,
    primaryKeyId
  };
}

export function createEncryptedSnapshotStoreFromEnvironment(env = process.env) {
  const directory = env.WORKFORCE_AUDIT_DATA_DIR ?? '.runtime-data/workforce-audit';
  if (!env.WORKFORCE_AUDIT_ENCRYPTION_KEYS) {
    if (env.NODE_ENV === 'production') {
      throw new Error('WORKFORCE_AUDIT_ENCRYPTION_KEYS is required in production.');
    }
    const keyId = 'local-dev-v1';
    const key = createHash('sha256').update('basitclaw-local-development-only').digest();
    return createEncryptedSnapshotStore({ directory, keys: { [keyId]: key.toString('base64') }, primaryKeyId: keyId });
  }

  let keys;
  try { keys = JSON.parse(env.WORKFORCE_AUDIT_ENCRYPTION_KEYS); } catch {
    throw new Error('WORKFORCE_AUDIT_ENCRYPTION_KEYS must be valid JSON.');
  }
  const primaryKeyId = env.WORKFORCE_AUDIT_PRIMARY_KEY_ID;
  if (!primaryKeyId) throw new Error('WORKFORCE_AUDIT_PRIMARY_KEY_ID is required when encryption keys are configured.');
  return createEncryptedSnapshotStore({ directory, keys, primaryKeyId });
}

export function hashTenantIdentifier(tenantId) {
  validateTenantId(tenantId);
  return createHash('sha256').update(tenantId).digest('hex');
}

function decryptEnvelope(envelope, tenantId, keyring) {
  const key = keyring.get(envelope.keyId);
  if (!key) {
    throw new PersistenceError('The snapshot encryption key is not available.', {
      tenantId,
      keyId: envelope.keyId,
      operation: 'decrypt'
    });
  }
  try {
    const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(Buffer.from(associatedData(envelope)));
    decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
      decipher.final()
    ]).toString('utf8');
    const snapshot = JSON.parse(plaintext);
    validateSnapshot(snapshot, tenantId);
    return snapshot;
  } catch (error) {
    if (error instanceof PersistenceError) throw error;
    throw new PersistenceError('Encrypted workforce-audit state could not be decrypted.', {
      tenantId,
      keyId: envelope.keyId,
      operation: 'decrypt'
    }, error);
  }
}

function atomicWrite(targetPath, content, tenantId, operation) {
  const temporaryPath = `${targetPath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  let fileDescriptor;
  try {
    fileDescriptor = openSync(temporaryPath, 'wx', 0o600);
    writeFileSync(fileDescriptor, content, 'utf8');
    fsyncSync(fileDescriptor);
    closeSync(fileDescriptor);
    fileDescriptor = undefined;
    renameSync(temporaryPath, targetPath);
    fsyncDirectory(dirname(targetPath));
  } catch (error) {
    if (fileDescriptor !== undefined) {
      try { closeSync(fileDescriptor); } catch {}
    }
    try { unlinkSync(temporaryPath); } catch {}
    throw new PersistenceError('Encrypted workforce-audit state could not be written.', {
      tenantId,
      operation
    }, error);
  }
}

function normaliseSerializedEnvelope(serialized) {
  const text = Buffer.isBuffer(serialized) ? serialized.toString('utf8') : String(serialized ?? '');
  if (!text.trim()) throw new TypeError('Encrypted snapshot envelope is empty.');
  if (Buffer.byteLength(text, 'utf8') > MAX_ENCRYPTED_BYTES) throw new TypeError('Encrypted snapshot envelope exceeds the 64 MB limit.');
  return text;
}

function normaliseKeyring(keys) {
  if (!keys || typeof keys !== 'object' || Array.isArray(keys)) throw new TypeError('Encryption keys must be an object keyed by key ID.');
  const keyring = new Map();
  for (const [keyId, encoded] of Object.entries(keys)) {
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(keyId)) throw new TypeError('Encryption key IDs must be safe identifiers.');
    const key = Buffer.isBuffer(encoded) ? encoded : Buffer.from(String(encoded), 'base64');
    if (key.length !== 32) throw new TypeError(`Encryption key ${keyId} must decode to exactly 32 bytes.`);
    keyring.set(keyId, key);
  }
  if (keyring.size === 0) throw new TypeError('At least one encryption key is required.');
  return keyring;
}

function validateSnapshot(snapshot, tenantId) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new TypeError('Snapshot must be an object.');
  if (snapshot.schemaVersion !== 1) throw new TypeError('Unsupported workforce-audit snapshot schema version.');
  if (snapshot.tenantId !== tenantId) throw new TypeError('Snapshot tenant does not match the requested tenant.');
  if (!snapshot.state || !Array.isArray(snapshot.state.engagements) || !Array.isArray(snapshot.state.findings)) {
    throw new TypeError('Snapshot state is incomplete.');
  }
  if (!Array.isArray(snapshot.governanceEvents)) throw new TypeError('Snapshot governanceEvents must be an array.');
}

function validateEnvelope(envelope, tenantId) {
  if (!envelope || envelope.format !== FORMAT || envelope.version !== ENVELOPE_VERSION || envelope.algorithm !== ALGORITHM) {
    throw new PersistenceError('Unsupported encrypted snapshot envelope.', { tenantId, operation: 'load' });
  }
  if (envelope.tenantHash !== hashTenantIdentifier(tenantId)) {
    throw new PersistenceError('Encrypted snapshot tenant binding is invalid.', { tenantId, operation: 'load' });
  }
  for (const field of ['keyId', 'writtenAt', 'iv', 'authTag', 'ciphertext']) {
    if (typeof envelope[field] !== 'string' || envelope[field].length === 0) {
      throw new PersistenceError(`Encrypted snapshot field ${field} is missing.`, { tenantId, operation: 'load' });
    }
  }
}

function associatedData(envelope) {
  return JSON.stringify({
    format: envelope.format,
    version: envelope.version,
    algorithm: envelope.algorithm,
    keyId: envelope.keyId,
    tenantHash: envelope.tenantHash,
    writtenAt: envelope.writtenAt,
    iv: envelope.iv
  });
}

function tenantPath(directory, tenantId) {
  return resolve(directory, `${hashTenantIdentifier(tenantId)}.snapshot.enc`);
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
}

function fsyncDirectory(directory) {
  let descriptor;
  try {
    descriptor = openSync(directory, 'r');
    fsyncSync(descriptor);
  } catch {
    // Some platforms do not support directory fsync. The file itself was fsynced before rename.
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch {}
    }
  }
}
