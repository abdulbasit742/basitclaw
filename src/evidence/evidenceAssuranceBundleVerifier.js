import {
  constants,
  createDecipheriv,
  createPrivateKey,
  privateDecrypt,
  timingSafeEqual
} from 'node:crypto';
import { sha256, strictBase64 } from './evidenceCrypto.js';

const SEALED_FORMAT = 'basitclaw-recipient-sealed-assurance-bundle';
const PACKAGE_FORMAT = 'basitclaw-assurance-bundle-package';
const MANIFEST_FORMAT = 'basitclaw-assurance-bundle-manifest';
const BUNDLE_ID = /^ASB-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MAX_PACKAGE_BYTES = 100_000_000;

export class EvidenceAssuranceBundleVerificationError extends Error {
  constructor(message = 'The assurance bundle could not be verified.', { code = 'EVIDENCE_ASSURANCE_BUNDLE_VERIFICATION_FAILED', details = {}, cause = null } = {}) {
    super(message, { cause: cause ?? undefined });
    this.name = 'EvidenceAssuranceBundleVerificationError';
    this.code = code;
    this.details = details;
  }
}

export function verifyEvidenceAssuranceBundle({
  sealedPackage,
  privateKeyPem,
  expectedBundleId = null,
  expectedPackageSha256 = null,
  expectedRecipientPublicKeyId = null,
  requireOperationallyAcceptable = true,
  now = () => new Date()
} = {}) {
  const sealed = validateSealedPackage(sealedPackage);
  const expectedBundle = expectedBundleId === null ? null : bundleIdentifier(expectedBundleId);
  const expectedPackageHash = expectedPackageSha256 === null ? null : hashValue(expectedPackageSha256, 'expectedPackageSha256');
  const expectedKeyId = expectedRecipientPublicKeyId === null ? null : identifier(expectedRecipientPublicKeyId, 'expectedRecipientPublicKeyId');
  if (expectedKeyId && sealed.recipientPublicKeyId !== expectedKeyId) fail('The sealed package references an unexpected recipient public key.', 'RECIPIENT_KEY_MISMATCH', { expected: expectedKeyId, actual: sealed.recipientPublicKeyId });

  const packageSha256 = sha256(stableStringify(sealed));
  if (expectedPackageHash && !safeEqualHex(packageSha256, expectedPackageHash)) fail('The sealed package digest does not match the expected claim digest.', 'PACKAGE_DIGEST_MISMATCH', { expected: expectedPackageHash, actual: packageSha256 });

  let privateKey;
  try {
    privateKey = createPrivateKey(String(privateKeyPem ?? ''));
  } catch (error) {
    fail('The recipient private key is invalid.', 'INVALID_RECIPIENT_PRIVATE_KEY', {}, error);
  }
  if (privateKey.asymmetricKeyType !== 'rsa') fail('The recipient private key must be RSA.', 'INVALID_RECIPIENT_PRIVATE_KEY', { asymmetricKeyType: privateKey.asymmetricKeyType });
  if ((privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) fail('The recipient RSA private key must be at least 2048 bits.', 'WEAK_RECIPIENT_PRIVATE_KEY', { modulusLength: privateKey.asymmetricKeyDetails?.modulusLength ?? null });

  const plaintext = decryptSealed(sealed, privateKey);
  if (plaintext.length > MAX_PACKAGE_BYTES) fail('The decrypted assurance bundle exceeds the supported size.', 'PACKAGE_TOO_LARGE', { maximumBytes: MAX_PACKAGE_BYTES, actualBytes: plaintext.length });
  const plaintextSha256 = sha256(plaintext);
  if (!safeEqualHex(plaintextSha256, sealed.plaintextSha256)) fail('The decrypted assurance bundle digest is invalid.', 'PLAINTEXT_DIGEST_MISMATCH', { expected: sealed.plaintextSha256, actual: plaintextSha256 });

  let payload;
  try { payload = JSON.parse(plaintext.toString('utf8')); }
  catch (error) { fail('The decrypted assurance bundle is not valid JSON.', 'INVALID_PACKAGE_JSON', {}, error); }
  validatePayloadIdentity(payload, sealed, expectedBundle);

  const manifest = validateManifest(payload.manifest, payload);
  const sections = validateSections(payload.evidence);
  const sectionResults = verifySectionDigests(manifest.sectionDigests, sections);
  const manifestWithoutDigest = structuredClone(manifest);
  delete manifestWithoutDigest.bundleDigest;
  const calculatedBundleDigest = sha256(stableStringify(manifestWithoutDigest));
  if (!safeEqualHex(calculatedBundleDigest, manifest.bundleDigest)) fail('The assurance bundle manifest digest is invalid.', 'MANIFEST_DIGEST_MISMATCH', { expected: manifest.bundleDigest, actual: calculatedBundleDigest });

  const evidenceResult = verifyEvidenceContent(sections, payload, manifest);
  const posture = verifyPosture(sections, manifest, requireOperationallyAcceptable);
  const expiration = verifyExpiration(payload, now);

  plaintext.fill(0);
  return Object.freeze({
    valid: true,
    bundleId: payload.bundleId,
    recipientId: payload.recipientId,
    recipientPublicKeyId: sealed.recipientPublicKeyId,
    evidenceId: payload.evidenceId,
    evidenceVersion: payload.evidenceVersion,
    contentSha256: evidenceResult.contentSha256,
    sizeBytes: evidenceResult.sizeBytes,
    packageSha256,
    plaintextSha256,
    manifestDigest: manifest.bundleDigest,
    sectionDigests: sectionResults,
    custodyVerified: posture.custodyVerified,
    operationallyAcceptable: posture.operationallyAcceptable,
    notaryGovernanceArchives: posture.governedArchives,
    createdAt: payload.createdAt,
    expiresAt: payload.expiresAt,
    expired: expiration.expired,
    verifiedAt: now().toISOString(),
    warnings: Object.freeze(expiration.warnings)
  });
}

function decryptSealed(sealed, privateKey) {
  let contentKey;
  try {
    contentKey = privateDecrypt({
      key: privateKey,
      oaepHash: 'sha256',
      padding: constants.RSA_PKCS1_OAEP_PADDING
    }, strictBase64(sealed.wrappedKey, 'wrappedKey'));
    if (contentKey.length !== 32) fail('The unwrapped assurance bundle key is invalid.', 'INVALID_CONTENT_KEY', { bytes: contentKey.length });
    const decipher = createDecipheriv('aes-256-gcm', contentKey, strictBase64(sealed.iv, 'iv'));
    decipher.setAAD(strictBase64(sealed.aad, 'aad'));
    decipher.setAuthTag(strictBase64(sealed.tag, 'tag'));
    return Buffer.concat([decipher.update(strictBase64(sealed.ciphertext, 'ciphertext')), decipher.final()]);
  } catch (error) {
    if (error instanceof EvidenceAssuranceBundleVerificationError) throw error;
    fail('The assurance bundle could not be decrypted or authenticated.', 'PACKAGE_DECRYPTION_FAILED', {}, error);
  } finally {
    contentKey?.fill?.(0);
  }
}

function validateSealedPackage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('A sealed assurance bundle package is required.', 'INVALID_SEALED_PACKAGE');
  const allowed = new Set(['format','version','algorithm','recipientPublicKeyId','iv','tag','aad','wrappedKey','ciphertext','plaintextSha256']);
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`The sealed assurance bundle contains unsupported field ${key}.`, 'UNSUPPORTED_SEALED_FIELD', { field: key });
  if (value.format !== SEALED_FORMAT || value.version !== 1 || value.algorithm !== 'RSA-OAEP-SHA256+A256GCM') fail('The sealed assurance bundle format or algorithm is unsupported.', 'UNSUPPORTED_SEALED_FORMAT');
  const sealed = {
    format: value.format,
    version: value.version,
    algorithm: value.algorithm,
    recipientPublicKeyId: identifier(value.recipientPublicKeyId, 'recipientPublicKeyId'),
    iv: base64Text(value.iv, 'iv', 12),
    tag: base64Text(value.tag, 'tag', 16),
    aad: base64Text(value.aad, 'aad', 1, 1024),
    wrappedKey: base64Text(value.wrappedKey, 'wrappedKey', 128, 2048),
    ciphertext: base64Text(value.ciphertext, 'ciphertext', 1, 150_000_000),
    plaintextSha256: hashValue(value.plaintextSha256, 'plaintextSha256')
  };
  return Object.freeze(sealed);
}

function validatePayloadIdentity(payload, sealed, expectedBundle) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail('The decrypted assurance bundle payload is invalid.', 'INVALID_PACKAGE');
  if (payload.format !== PACKAGE_FORMAT || payload.version !== 1) fail('The assurance bundle package format is unsupported.', 'UNSUPPORTED_PACKAGE_FORMAT');
  const bundleId = bundleIdentifier(payload.bundleId);
  if (expectedBundle && bundleId !== expectedBundle) fail('The assurance bundle ID does not match the expected claim.', 'BUNDLE_ID_MISMATCH', { expected: expectedBundle, actual: bundleId });
  const aadText = strictBase64(sealed.aad, 'aad').toString('utf8');
  const expectedAad = `basitclaw:assurance-bundle:${bundleId}:${sealed.recipientPublicKeyId}`;
  if (aadText !== expectedAad) fail('The sealed package AAD does not bind the bundle and recipient key.', 'AAD_BINDING_MISMATCH', { expected: expectedAad, actual: aadText });
  if (identifier(payload.recipientId, 'recipientId') !== identifier(payload.manifest?.recipientId, 'manifest.recipientId')) fail('Recipient identity differs between package and manifest.', 'RECIPIENT_ID_MISMATCH');
  if (bundleId !== payload.bundleId) fail('The package bundle ID is invalid.', 'BUNDLE_ID_MISMATCH');
}

function validateManifest(manifest, payload) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) fail('The assurance bundle manifest is missing.', 'INVALID_MANIFEST');
  if (manifest.format !== MANIFEST_FORMAT || manifest.version !== 1) fail('The assurance bundle manifest format is unsupported.', 'UNSUPPORTED_MANIFEST_FORMAT');
  const result = structuredClone(manifest);
  result.bundleDigest = hashValue(result.bundleDigest, 'manifest.bundleDigest');
  result.contentSha256 = hashValue(result.contentSha256, 'manifest.contentSha256');
  if (bundleIdentifier(payload.bundleId) !== bundleIdentifier(payload.bundleId)) fail('The bundle identity is invalid.', 'BUNDLE_ID_MISMATCH');
  if (result.evidenceId !== payload.evidenceId || Number(result.evidenceVersion) !== Number(payload.evidenceVersion) || result.recipientId !== payload.recipientId) fail('Package and manifest identities differ.', 'MANIFEST_IDENTITY_MISMATCH');
  if (!result.sectionDigests || typeof result.sectionDigests !== 'object' || Array.isArray(result.sectionDigests)) fail('The manifest section digest map is invalid.', 'INVALID_SECTION_DIGESTS');
  return result;
}

function validateSections(sections) {
  if (!sections || typeof sections !== 'object' || Array.isArray(sections)) fail('The assurance bundle sections are missing.', 'INVALID_SECTIONS');
  return sections;
}

function verifySectionDigests(expected, sections) {
  const expectedNames = Object.keys(expected).sort();
  const sectionNames = Object.keys(sections).sort();
  if (expectedNames.length !== sectionNames.length || expectedNames.some((name, index) => name !== sectionNames[index])) fail('The manifest section set does not match the package sections.', 'SECTION_SET_MISMATCH', { expected: expectedNames, actual: sectionNames });
  return Object.freeze(Object.fromEntries(sectionNames.map((name) => {
    const expectedDigest = hashValue(expected[name], `sectionDigests.${name}`);
    const actualDigest = sha256(stableStringify(sections[name]));
    if (!safeEqualHex(expectedDigest, actualDigest)) fail(`The assurance bundle section ${name} failed digest verification.`, 'SECTION_DIGEST_MISMATCH', { section: name, expected: expectedDigest, actual: actualDigest });
    return [name, actualDigest];
  })));
}

function verifyEvidenceContent(sections, payload, manifest) {
  const content = sections.content;
  if (!content || typeof content !== 'object' || Array.isArray(content)) fail('The evidence content section is missing.', 'MISSING_CONTENT_SECTION');
  const bytes = strictBase64(content.contentBase64, 'content.contentBase64');
  const contentSha256 = hashValue(content.sha256, 'content.sha256');
  const actualSha256 = sha256(bytes);
  const sizeBytes = integer(content.sizeBytes, 'content.sizeBytes', 0, MAX_PACKAGE_BYTES);
  if (bytes.length !== sizeBytes) fail('The evidence content size is invalid.', 'CONTENT_SIZE_MISMATCH', { expected: sizeBytes, actual: bytes.length });
  if (!safeEqualHex(contentSha256, actualSha256) || !safeEqualHex(contentSha256, manifest.contentSha256)) fail('The evidence content digest does not match its manifest.', 'CONTENT_DIGEST_MISMATCH', { expected: manifest.contentSha256, actual: actualSha256 });
  const version = sections.version;
  if (!version || Number(version.version) !== Number(payload.evidenceVersion) || !safeEqualHex(hashValue(version.sha256, 'version.sha256'), contentSha256) || Number(version.sizeBytes) !== sizeBytes) fail('The immutable version metadata does not match the evidence bytes.', 'VERSION_METADATA_MISMATCH');
  bytes.fill(0);
  return { contentSha256, sizeBytes };
}

function verifyPosture(sections, manifest, requireOperationallyAcceptable) {
  const assurance = sections.assurancePosture;
  const verification = sections.verification;
  if (!assurance || typeof assurance !== 'object' || !verification || typeof verification !== 'object') fail('The assurance posture or custody verification section is missing.', 'MISSING_ASSURANCE_POSTURE');
  const custodyVerified = verification.valid === true && assurance.cryptographicallyVerified === true;
  if (!custodyVerified) fail('The exported evidence custody chain is not verified.', 'CUSTODY_NOT_VERIFIED');
  const operationallyAcceptable = assurance.operationallyAcceptable === true && manifest.operationallyAcceptable === true;
  const governedArchives = integer(assurance.governedArchives ?? 0, 'assurancePosture.governedArchives', 0, 1_000_000);
  const operationalQuorumArchives = integer(assurance.operationalQuorumArchives ?? 0, 'assurancePosture.operationalQuorumArchives', 0, 1_000_000);
  if (operationalQuorumArchives > governedArchives) fail('The assurance posture archive counts are inconsistent.', 'ASSURANCE_POSTURE_MISMATCH');
  if (requireOperationallyAcceptable && !operationallyAcceptable) fail('The assurance bundle is cryptographically valid but operationally unacceptable.', 'OPERATIONAL_ASSURANCE_REJECTED', { governedArchives, operationalQuorumArchives });
  return { custodyVerified, operationallyAcceptable, governedArchives };
}

function verifyExpiration(payload, now) {
  const createdAt = isoDate(payload.createdAt, 'createdAt');
  const expiresAt = isoDate(payload.expiresAt, 'expiresAt');
  if (new Date(expiresAt) <= new Date(createdAt)) fail('The assurance bundle expiry is not after creation.', 'INVALID_EXPIRATION');
  const expired = now() >= new Date(expiresAt);
  return { expired, warnings: expired ? ['The assurance bundle delivery window has expired; verify recipient policy before relying on it.'] : [] };
}

function base64Text(value, field, minimum, maximum = minimum) {
  let bytes;
  try { bytes = strictBase64(String(value ?? ''), field); }
  catch (error) { fail(`${field} must be canonical base64.`, 'INVALID_BASE64', { field }, error); }
  if (bytes.length < minimum || bytes.length > maximum) fail(`${field} has an invalid decoded length.`, 'INVALID_BASE64_LENGTH', { field, minimum, maximum, actual: bytes.length });
  return bytes.toString('base64');
}
function bundleIdentifier(value) { const text = String(value ?? ''); if (!BUNDLE_ID.test(text)) fail('bundleId is invalid.', 'INVALID_BUNDLE_ID'); return text; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!HASH.test(text)) fail(`${field} must be a SHA-256 digest.`, 'INVALID_HASH', { field }); return text; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) fail(`${field} is invalid.`, 'INVALID_IDENTIFIER', { field }); return text; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) fail(`${field} must be an integer from ${minimum} to ${maximum}.`, 'INVALID_INTEGER', { field }); return parsed; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) fail(`${field} must be a valid ISO date.`, 'INVALID_DATE', { field }); return date.toISOString(); }
function safeEqualHex(left, right) { const a = Buffer.from(String(left), 'hex'); const b = Buffer.from(String(right), 'hex'); return a.length === b.length && timingSafeEqual(a, b); }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
function fail(message, code, details = {}, cause = null) { throw new EvidenceAssuranceBundleVerificationError(message, { code, details, cause }); }
