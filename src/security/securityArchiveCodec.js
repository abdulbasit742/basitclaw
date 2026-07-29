import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const FORMAT = 'basitclaw-security-archive';

export function createSecurityArchiveCodec({
  masterKey,
  keyId = 'security-archive-v1',
  keys = null,
  primaryKeyId = null
} = {}) {
  const environmentKeys = keys ? null : parseKeyring(process.env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS);
  const effectiveKeys = keys ?? environmentKeys;
  const effectivePrimaryKeyId = primaryKeyId
    ?? (effectiveKeys ? process.env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID : null)
    ?? (effectiveKeys ? Object.keys(effectiveKeys)[0] : keyId);
  const materials = createMaterials({ masterKey, keyId, keys: effectiveKeys });
  const primaryId = safeIdentifier(effectivePrimaryKeyId, 'primaryKeyId');
  if (!materials.has(primaryId)) throw new TypeError('Security archive primary key ID is not present in the keyring.');
  const legacySingleKey = !effectiveKeys;

  function seal(event, { sequence, previousHash, writtenAt }) {
    const material = materials.get(primaryId);
    const payload = Buffer.from(JSON.stringify({ archivedAt: writtenAt, event }), 'utf8');
    const iv = randomBytes(12);
    const aadValue = { format: FORMAT, version: 1, sequence, previousHash, keyId: primaryId };
    const cipher = createCipheriv('aes-256-gcm', material.encryptionKey, iv);
    cipher.setAAD(Buffer.from(stableStringify(aadValue), 'utf8'));
    const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
    const unsigned = {
      format: FORMAT,
      version: 1,
      archiveId: `SARC-${String(sequence).padStart(12, '0')}`,
      sequence,
      writtenAt,
      sourceEventId: String(event.id ?? '').slice(0, 128) || null,
      previousHash,
      keyId: primaryId,
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64')
    };
    return { ...unsigned, hash: signWith(material, unsigned) };
  }

  function open(envelope) {
    verifyEnvelope(envelope);
    const material = materialFor(envelope.keyId, envelope.archiveId);
    try {
      const aadValue = {
        format: FORMAT,
        version: 1,
        sequence: envelope.sequence,
        previousHash: envelope.previousHash,
        keyId: envelope.keyId
      };
      const decipher = createDecipheriv('aes-256-gcm', material.encryptionKey, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(stableStringify(aadValue), 'utf8'));
      decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
      return JSON.parse(Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
        decipher.final()
      ]).toString('utf8'));
    } catch {
      const error = new Error('A security archive envelope could not be decrypted.');
      error.archiveId = envelope.archiveId;
      error.keyId = envelope.keyId;
      throw error;
    }
  }

  function verifyEnvelope(envelope) {
    if (envelope?.format !== FORMAT || envelope.version !== 1 || !Number.isInteger(envelope.sequence)) {
      const error = new Error('A security archive envelope failed validation.');
      error.archiveId = envelope?.archiveId ?? null;
      throw error;
    }
    const material = materialFor(envelope.keyId, envelope.archiveId);
    const { hash, ...unsigned } = envelope;
    if (!constantEqual(hash, signWith(material, unsigned))) {
      const error = new Error('A security archive envelope signature is invalid.');
      error.archiveId = envelope.archiveId;
      error.keyId = envelope.keyId;
      throw error;
    }
    return true;
  }

  function signAnchor(anchor) {
    return signPurpose(materials.get(primaryId), 'anchor', anchor);
  }

  function signPrunePlan(plan) {
    return signPurpose(materials.get(primaryId), 'prune', plan);
  }

  function identifySignedKey(value, signature, signer, keyIdHint = null) {
    const purpose = signer === signAnchor ? 'anchor' : signer === signPrunePlan ? 'prune' : null;
    if (!purpose) throw new TypeError('Security archive signed-value verifier is invalid.');
    const candidates = keyIdHint ? [[safeIdentifier(keyIdHint, 'keyId'), materialFor(keyIdHint)]] : [...materials.entries()];
    for (const [candidateId, material] of candidates) {
      if (constantEqual(signature, signPurpose(material, purpose, value))) return candidateId;
    }
    return null;
  }

  function verifySigned(value, signature, signer, keyIdHint = null) {
    return identifySignedKey(value, signature, signer, keyIdHint) !== null;
  }

  function materialFor(value, archiveId = null) {
    const requested = safeIdentifier(value, 'keyId');
    const material = materials.get(requested);
    if (!material) {
      const error = new Error('A required security archive key is not configured.');
      error.archiveId = archiveId;
      error.keyId = requested;
      throw error;
    }
    return material;
  }

  return {
    keyId: primaryId,
    primaryKeyId: primaryId,
    keyIds: [...materials.keys()],
    legacySingleKey,
    seal,
    open,
    verifyEnvelope,
    signAnchor,
    signPrunePlan,
    verifySigned,
    identifySignedKey,
    hasKey: (value) => materials.has(String(value))
  };
}

export function parseSecurityArchiveKeyring(value) {
  return parseKeyring(value);
}

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function createMaterials({ masterKey, keyId, keys }) {
  const entries = keys ? Object.entries(keys) : [[keyId, masterKey]];
  if (entries.length === 0) throw new TypeError('Security archive keyring must contain at least one key.');
  const materials = new Map();
  for (const [identifier, value] of entries) {
    const safeId = safeIdentifier(identifier, 'keyId');
    if (materials.has(safeId)) throw new TypeError('Security archive key IDs must be unique.');
    const key = normaliseKey(value);
    materials.set(safeId, {
      encryptionKey: deriveKey(key, 'encryption'),
      signingKey: deriveKey(key, 'signing')
    });
  }
  return materials;
}

function parseKeyring(value) {
  if (value === undefined || value === null || value === '') return null;
  let parsed;
  try { parsed = typeof value === 'string' ? JSON.parse(value) : value; } catch {
    throw new TypeError('WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS must be a JSON object.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
    throw new TypeError('Security archive keyring must be a non-empty object.');
  }
  return parsed;
}

function normaliseKey(value) {
  const key = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(String(value ?? ''), 'base64');
  if (key.length !== 32) throw new TypeError('Security archive encryption keys must be base64-encoded 32-byte keys.');
  return key;
}

function deriveKey(masterKey, purpose) {
  return createHmac('sha256', masterKey).update(`basitclaw-security-archive:${purpose}`).digest();
}

function signWith(material, value) {
  return createHmac('sha256', material.signingKey).update(stableStringify(value)).digest('hex');
}

function signPurpose(material, purpose, value) {
  return createHmac('sha256', material.signingKey).update(`${purpose}:${stableStringify(value)}`).digest('hex');
}

function constantEqual(left, right) {
  const a = Buffer.from(String(left ?? ''));
  const b = Buffer.from(String(right ?? ''));
  return a.length === b.length && timingSafeEqual(a, b);
}

function safeIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}
