import {
  constants,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  verify as verifySignature
} from 'node:crypto';

const PACKAGE_FORMAT = 'basitclaw-assurance-disclosure-package-v1';
const PAYLOAD_FORMAT = 'basitclaw-assurance-disclosure-payload-v1';
const BUNDLE_ID = /^DSC-[a-f0-9]{32}$/;

export class EvidenceDisclosureVerificationError extends Error {
  constructor(message, details = {}, cause = null) {
    super(message, { cause });
    this.name = 'EvidenceDisclosureVerificationError';
    this.code = 'EVIDENCE_DISCLOSURE_VERIFICATION_FAILED';
    this.details = details;
  }
}

export function verifyAndDecryptDisclosurePackage(packageValue, {
  recipientPrivateKey,
  enterprisePublicKeys,
  now = () => new Date(),
  allowExpired = false
} = {}) {
  const envelope = validatePackage(packageValue);
  const publicKey = resolveEnterprisePublicKey(enterprisePublicKeys, envelope.signingKeyId);
  verifyEnterpriseSignature(envelope, publicKey);

  const current = now();
  if (!(current instanceof Date) || Number.isNaN(current.getTime())) throw new TypeError('now must return a valid Date.');
  if (!allowExpired && current >= new Date(envelope.expiresAt)) {
    throw new EvidenceDisclosureVerificationError('The disclosure package has expired.', { expiresAt: envelope.expiresAt });
  }

  let contentKey;
  try {
    contentKey = privateDecrypt({
      key: createPrivateKey(recipientPrivateKey),
      oaepHash: 'sha256',
      padding: constants.RSA_PKCS1_OAEP_PADDING
    }, strictBase64(envelope.wrappedKey, 'wrappedKey'));
  } catch (error) {
    throw new EvidenceDisclosureVerificationError('The recipient private key cannot unwrap this disclosure package.', {
      recipientKeyId: envelope.recipientKeyId
    }, error);
  }
  if (contentKey.length !== 32) throw new EvidenceDisclosureVerificationError('The unwrapped disclosure content key is invalid.');

  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', contentKey, strictBase64(envelope.iv, 'iv'));
    decipher.setAAD(Buffer.from(packageAad(envelope)));
    decipher.setAuthTag(strictBase64(envelope.tag, 'tag'));
    plaintext = Buffer.concat([
      decipher.update(strictBase64(envelope.ciphertext, 'ciphertext')),
      decipher.final()
    ]);
  } catch (error) {
    throw new EvidenceDisclosureVerificationError('Disclosure package authentication failed.', {}, error);
  }

  if (sha256(plaintext) !== envelope.payloadSha256) {
    throw new EvidenceDisclosureVerificationError('The decrypted disclosure payload digest does not match the package manifest.');
  }

  let payload;
  try { payload = JSON.parse(plaintext.toString('utf8')); }
  catch (error) { throw new EvidenceDisclosureVerificationError('The disclosure payload is not valid JSON.', {}, error); }
  validatePayload(payload, envelope);

  const { manifestSha256, ...manifestBody } = payload;
  if (sha256(stableStringify(manifestBody)) !== manifestSha256) {
    throw new EvidenceDisclosureVerificationError('The disclosure payload manifest digest is invalid.');
  }

  return Object.freeze({
    valid: true,
    bundleId: envelope.bundleId,
    signingKeyId: envelope.signingKeyId,
    recipientKeyId: envelope.recipientKeyId,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    manifestSha256,
    evidenceReference: payload.evidence?.evidenceReference ?? null,
    versionCount: Array.isArray(payload.evidence?.versions) ? payload.evidence.versions.length : 0,
    payload
  });
}

export function verifyDisclosurePackageSignature(packageValue, enterprisePublicKeys) {
  const envelope = validatePackage(packageValue);
  verifyEnterpriseSignature(envelope, resolveEnterprisePublicKey(enterprisePublicKeys, envelope.signingKeyId));
  return Object.freeze({
    valid: true,
    bundleId: envelope.bundleId,
    signingKeyId: envelope.signingKeyId,
    recipientKeyId: envelope.recipientKeyId,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    ciphertextSha256: envelope.ciphertextSha256
  });
}

export function disclosurePayload(body) {
  const value = { format: PAYLOAD_FORMAT, version: 1, ...body };
  return Object.freeze({ ...value, manifestSha256: sha256(stableStringify(value)) });
}

export function disclosurePackageSignatureBody(envelope) {
  return stableStringify({
    format: envelope.format,
    version: envelope.version,
    bundleId: envelope.bundleId,
    recipientKeyId: envelope.recipientKeyId,
    wrappingAlgorithm: envelope.wrappingAlgorithm,
    contentAlgorithm: envelope.contentAlgorithm,
    signingAlgorithm: envelope.signingAlgorithm,
    signingKeyId: envelope.signingKeyId,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    payloadSha256: envelope.payloadSha256,
    ciphertextSha256: envelope.ciphertextSha256,
    wrappedKey: envelope.wrappedKey,
    iv: envelope.iv,
    tag: envelope.tag
  });
}

export function packageAad(envelope) {
  return stableStringify({
    format: envelope.format,
    version: envelope.version,
    bundleId: envelope.bundleId,
    recipientKeyId: envelope.recipientKeyId,
    createdAt: envelope.createdAt,
    expiresAt: envelope.expiresAt,
    payloadSha256: envelope.payloadSha256
  });
}

export function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function validatePackage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new EvidenceDisclosureVerificationError('A disclosure package object is required.');
  if (value.format !== PACKAGE_FORMAT || value.version !== 1 || !BUNDLE_ID.test(String(value.bundleId ?? ''))) {
    throw new EvidenceDisclosureVerificationError('The disclosure package identity is invalid.');
  }
  if (value.wrappingAlgorithm !== 'rsa-oaep-sha256' || value.contentAlgorithm !== 'aes-256-gcm') {
    throw new EvidenceDisclosureVerificationError('The disclosure package algorithms are unsupported.');
  }
  if (!['ed25519', 'rsa-pss-sha256'].includes(value.signingAlgorithm)) {
    throw new EvidenceDisclosureVerificationError('The disclosure signature algorithm is unsupported.');
  }
  for (const field of ['recipientKeyId', 'signingKeyId']) safeId(value[field], field);
  for (const field of ['createdAt', 'expiresAt']) validDate(value[field], field);
  for (const field of ['payloadSha256', 'ciphertextSha256']) digest(value[field], field);
  for (const field of ['wrappedKey', 'iv', 'tag', 'ciphertext', 'signature']) strictBase64(value[field], field);
  if (sha256(strictBase64(value.ciphertext, 'ciphertext')) !== value.ciphertextSha256) {
    throw new EvidenceDisclosureVerificationError('The disclosure ciphertext digest is invalid.');
  }
  return value;
}

function validatePayload(payload, envelope) {
  if (!payload || payload.format !== PAYLOAD_FORMAT || payload.version !== 1 || payload.bundleId !== envelope.bundleId) {
    throw new EvidenceDisclosureVerificationError('The disclosure payload identity is invalid.');
  }
  if (payload.createdAt !== envelope.createdAt || payload.expiresAt !== envelope.expiresAt) {
    throw new EvidenceDisclosureVerificationError('The disclosure payload timestamps do not match the package.');
  }
  digest(payload.manifestSha256, 'manifestSha256');
  if (!payload.policy || payload.policy.rawEvidenceIncluded !== false) {
    throw new EvidenceDisclosureVerificationError('The disclosure payload does not enforce the metadata-only policy.');
  }
}

function verifyEnterpriseSignature(envelope, publicKey) {
  const body = Buffer.from(disclosurePackageSignatureBody(envelope));
  const signature = strictBase64(envelope.signature, 'signature');
  let valid = false;
  try {
    valid = envelope.signingAlgorithm === 'ed25519'
      ? verifySignature(null, body, publicKey, signature)
      : verifySignature('sha256', body, {
        key: publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32
      }, signature);
  } catch (error) {
    throw new EvidenceDisclosureVerificationError('The enterprise disclosure signature could not be evaluated.', {}, error);
  }
  if (!valid) throw new EvidenceDisclosureVerificationError('The enterprise disclosure signature is invalid.');
}

function resolveEnterprisePublicKey(raw, keyId) {
  const value = raw instanceof Map ? raw.get(keyId) : raw?.[keyId];
  if (!value) throw new EvidenceDisclosureVerificationError('The enterprise disclosure public key is unavailable.', { signingKeyId: keyId });
  if (value?.type === 'public' && typeof value.export === 'function') return value;
  try { return createPublicKey(value); }
  catch (error) { throw new EvidenceDisclosureVerificationError('The enterprise disclosure public key is invalid.', { signingKeyId: keyId }, error); }
}

function strictBase64(value, field) {
  const text = String(value ?? '');
  if (!text || !/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new EvidenceDisclosureVerificationError(`${field} is not canonical base64.`);
  const decoded = Buffer.from(text, 'base64');
  if (decoded.toString('base64') !== text) throw new EvidenceDisclosureVerificationError(`${field} is not canonical base64.`);
  return decoded;
}
function sha256(value) { return createHash('sha256').update(value).digest('hex'); }
function safeId(value, field) { if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(String(value ?? ''))) throw new EvidenceDisclosureVerificationError(`${field} is invalid.`); }
function digest(value, field) { if (!/^[a-f0-9]{64}$/.test(String(value ?? ''))) throw new EvidenceDisclosureVerificationError(`${field} is invalid.`); }
function validDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceDisclosureVerificationError(`${field} is invalid.`); }
