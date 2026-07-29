import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

export function parseEvidenceKeyring(rawKeys, primaryKeyId) {
  if (!rawKeys || typeof rawKeys !== 'object' || Array.isArray(rawKeys)) throw new TypeError('Evidence encryption keys must be an object.');
  const entries = Object.entries(rawKeys);
  if (!entries.length || entries.length > 100) throw new TypeError('Evidence encryption keys must contain 1 to 100 entries.');
  const keys = new Map(entries.map(([id, encoded]) => {
    safeId(id, 'keyId');
    const key = strictBase64(encoded, `key ${id}`);
    if (key.length !== 32) throw new TypeError(`Evidence encryption key ${id} must decode to 32 bytes.`);
    return [id, key];
  }));
  const primary = String(primaryKeyId ?? entries[0][0]);
  if (!keys.has(primary)) throw new TypeError('The evidence primary key ID is not present in the keyring.');
  return Object.freeze({ keys, primaryKeyId: primary });
}

export function encryptEvidenceJson(payload, keyring, aad) {
  const keyId = keyring.primaryKeyId;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyring.keys.get(keyId), iv);
  cipher.setAAD(Buffer.from(aad));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return {
    format: 'basitclaw-encrypted-envelope',
    version: 1,
    algorithm: 'aes-256-gcm',
    keyId,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

export function decryptEvidenceJson(envelope, keyring, aad, IntegrityError) {
  try {
    if (!envelope || envelope.format !== 'basitclaw-encrypted-envelope' || envelope.algorithm !== 'aes-256-gcm') throw new Error('invalid_envelope');
    const key = keyring.keys.get(envelope.keyId);
    if (!key) throw new Error('missing_key');
    const decipher = createDecipheriv('aes-256-gcm', key, strictBase64(envelope.iv, 'iv'));
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(strictBase64(envelope.tag, 'tag'));
    const plaintext = Buffer.concat([decipher.update(strictBase64(envelope.ciphertext, 'ciphertext')), decipher.final()]);
    return JSON.parse(plaintext.toString('utf8'));
  } catch (error) {
    throw new IntegrityError('Encrypted evidence authentication failed.', { keyId: envelope?.keyId ?? null }, error);
  }
}

export function atomicWriteEvidenceJson(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  let descriptor = null;
  try {
    descriptor = openSync(temporary, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = null;
    renameSync(temporary, path);
    const directory = openSync(dirname(path), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } catch (error) {
    if (descriptor !== null) try { closeSync(descriptor); } catch {}
    try { rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

export function readEvidenceJson(path) { return JSON.parse(readFileSync(path, 'utf8')); }
export function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
export function tenantEvidenceDirectory(root, tenantId) {
  const path = resolve(root, sha256(tenantId));
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}
export function strictBase64(value, field = 'value') {
  const text = String(value ?? '');
  if (!text || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new TypeError(`${field} must be valid base64.`);
  const decoded = Buffer.from(text, 'base64');
  if (decoded.toString('base64') !== text) throw new TypeError(`${field} must be canonical base64.`);
  return decoded;
}
function safeId(value, field) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(String(value ?? ''))) throw new TypeError(`${field} must be a safe identifier.`);
}
