import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const FORMAT = 'basitclaw-security-archive';

export function createSecurityArchiveCodec({ masterKey, keyId = 'security-archive-v1' } = {}) {
  const key = normaliseKey(masterKey);
  const encryptionKey = deriveKey(key, 'encryption');
  const signingKey = deriveKey(key, 'signing');
  const safeKeyId = safeIdentifier(keyId, 'keyId');

  function seal(event, { sequence, previousHash, writtenAt }) {
    const payload = Buffer.from(JSON.stringify({ archivedAt: writtenAt, event }), 'utf8');
    const iv = randomBytes(12);
    const aadValue = { format: FORMAT, version: 1, sequence, previousHash, keyId: safeKeyId };
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
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
      keyId: safeKeyId,
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64')
    };
    return { ...unsigned, hash: sign(unsigned) };
  }

  function open(envelope) {
    verifyEnvelope(envelope);
    try {
      const aadValue = {
        format: FORMAT,
        version: 1,
        sequence: envelope.sequence,
        previousHash: envelope.previousHash,
        keyId: envelope.keyId
      };
      const decipher = createDecipheriv('aes-256-gcm', encryptionKey, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(Buffer.from(stableStringify(aadValue), 'utf8'));
      decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
      return JSON.parse(Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
        decipher.final()
      ]).toString('utf8'));
    } catch {
      const error = new Error('A security archive envelope could not be decrypted.');
      error.archiveId = envelope.archiveId;
      throw error;
    }
  }

  function verifyEnvelope(envelope) {
    if (envelope?.format !== FORMAT || envelope.version !== 1 || !Number.isInteger(envelope.sequence)) {
      const error = new Error('A security archive envelope failed validation.');
      error.archiveId = envelope?.archiveId ?? null;
      throw error;
    }
    const { hash, ...unsigned } = envelope;
    if (!constantEqual(hash, sign(unsigned))) {
      const error = new Error('A security archive envelope signature is invalid.');
      error.archiveId = envelope.archiveId;
      throw error;
    }
    return true;
  }

  function signAnchor(anchor) {
    return createHmac('sha256', signingKey).update(`anchor:${stableStringify(anchor)}`).digest('hex');
  }

  function signPrunePlan(plan) {
    return createHmac('sha256', signingKey).update(`prune:${stableStringify(plan)}`).digest('hex');
  }

  function verifySigned(value, signature, signer) {
    return constantEqual(signature, signer(value));
  }

  function sign(value) {
    return createHmac('sha256', signingKey).update(stableStringify(value)).digest('hex');
  }

  return {
    keyId: safeKeyId,
    seal,
    open,
    verifyEnvelope,
    signAnchor,
    signPrunePlan,
    verifySigned
  };
}

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function normaliseKey(value) {
  const key = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(String(value ?? ''), 'base64');
  if (key.length !== 32) throw new TypeError('Security archive encryption key must be a base64-encoded 32-byte key.');
  return key;
}

function deriveKey(masterKey, purpose) {
  return createHmac('sha256', masterKey).update(`basitclaw-security-archive:${purpose}`).digest();
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
