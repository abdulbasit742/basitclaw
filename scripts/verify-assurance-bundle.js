import { constants, createDecipheriv, createPrivateKey, privateDecrypt } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { EvidenceIntegrityError, EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';

const SEALED_FORMAT = 'basitclaw-recipient-sealed-assurance-bundle';
const PACKAGE_FORMAT = 'basitclaw-assurance-bundle-package';
const MANIFEST_FORMAT = 'basitclaw-assurance-bundle-manifest';
const VERIFIER_VERSION = 'basitclaw-assurance-verifier/1';

export async function verifyAssuranceBundleFile({
  sealedPackagePath,
  recipientPrivateKeyPath,
  claimTokenPath = null,
  now = () => new Date()
} = {}) {
  if (!sealedPackagePath || !recipientPrivateKeyPath) throw new TypeError('sealedPackagePath and recipientPrivateKeyPath are required.');
  const sealedPackage = JSON.parse(await readFile(sealedPackagePath, 'utf8'));
  const privateKeyPem = await readFile(recipientPrivateKeyPath, 'utf8');
  const claimToken = claimTokenPath ? (await readFile(claimTokenPath, 'utf8')).trim() : null;
  return verifyAssuranceBundle({ sealedPackage, privateKeyPem, claimToken, now });
}

export function verifyAssuranceBundle({ sealedPackage, privateKeyPem, claimToken = null, now = () => new Date() } = {}) {
  validateSealedPackage(sealedPackage);
  const privateKey = createPrivateKey(String(privateKeyPem ?? ''));
  if (privateKey.asymmetricKeyType !== 'rsa' || (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new EvidenceValidationError('The assurance recipient private key must be RSA with at least 2048 bits.');
  }
  let contentKey;
  try {
    contentKey = privateDecrypt({
      key: privateKey,
      oaepHash: 'sha256',
      padding: constants.RSA_PKCS1_OAEP_PADDING
    }, canonicalBase64(sealedPackage.wrappedKey, 'wrappedKey'));
  } catch (error) {
    throw new EvidenceIntegrityError('The assurance bundle content key could not be unwrapped.', {}, error);
  }
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', contentKey, canonicalBase64(sealedPackage.iv, 'iv'));
    decipher.setAAD(canonicalBase64(sealedPackage.aad, 'aad'));
    decipher.setAuthTag(canonicalBase64(sealedPackage.tag, 'tag'));
    plaintext = Buffer.concat([
      decipher.update(canonicalBase64(sealedPackage.ciphertext, 'ciphertext')),
      decipher.final()
    ]);
  } catch (error) {
    throw new EvidenceIntegrityError('The assurance bundle AES-GCM authentication failed.', {}, error);
  } finally {
    contentKey?.fill?.(0);
  }
  const plaintextSha256 = sha256(plaintext);
  if (plaintextSha256 !== hashValue(sealedPackage.plaintextSha256, 'plaintextSha256')) {
    throw new EvidenceIntegrityError('The assurance bundle plaintext digest is invalid.');
  }
  let bundle;
  try { bundle = JSON.parse(plaintext.toString('utf8')); }
  catch (error) { throw new EvidenceIntegrityError('The assurance bundle plaintext is invalid JSON.', {}, error); }
  validateBundleIdentity(bundle, sealedPackage);
  verifyManifest(bundle);
  verifySections(bundle);
  verifyContent(bundle);

  const packageSha256 = sha256(stableStringify(sealedPackage));
  const sectionDigestsSha256 = sha256(stableStringify(bundle.manifest.sectionDigests));
  const verification = {
    packageSha256,
    plaintextSha256,
    bundleDigest: bundle.manifest.bundleDigest,
    sectionDigestsSha256,
    verifiedAt: now().toISOString(),
    verifierVersion: VERIFIER_VERSION
  };
  if (claimToken !== null) verification.claimToken = cleanToken(claimToken);
  return {
    valid: true,
    bundleId: bundle.bundleId,
    tenantId: bundle.tenantId,
    evidenceId: bundle.evidenceId,
    evidenceVersion: bundle.evidenceVersion,
    recipientId: bundle.recipientId,
    operationallyAcceptable: Boolean(bundle.manifest.operationallyAcceptable),
    packageSha256,
    plaintextSha256,
    bundleDigest: bundle.manifest.bundleDigest,
    sectionDigestsSha256,
    evidenceContentSha256: bundle.evidence.content.sha256,
    evidenceSizeBytes: bundle.evidence.content.sizeBytes,
    acceptanceRequest: verification
  };
}

function validateSealedPackage(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || value.format !== SEALED_FORMAT || value.version !== 1
      || value.algorithm !== 'RSA-OAEP-SHA256+A256GCM') {
    throw new EvidenceValidationError('The sealed assurance bundle format is invalid.');
  }
  keyIdentifier(value.recipientPublicKeyId);
  for (const field of ['iv', 'tag', 'aad', 'wrappedKey', 'ciphertext']) canonicalBase64(value[field], field);
}

function validateBundleIdentity(bundle, sealedPackage) {
  if (!bundle || bundle.format !== PACKAGE_FORMAT || bundle.version !== 1
      || !/^ASB-[a-f0-9]{32}$/.test(String(bundle.bundleId ?? ''))
      || !/^EVD-[a-f0-9]{32}$/.test(String(bundle.evidenceId ?? ''))
      || !Number.isInteger(bundle.evidenceVersion) || bundle.evidenceVersion < 1
      || typeof bundle.recipientId !== 'string' || !bundle.recipientId) {
    throw new EvidenceIntegrityError('The assurance bundle package identity is invalid.');
  }
  const expectedAad = Buffer.from(`basitclaw:assurance-bundle:${bundle.bundleId}:${sealedPackage.recipientPublicKeyId}`).toString('base64');
  if (sealedPackage.aad !== expectedAad) throw new EvidenceIntegrityError('The assurance bundle authenticated-data binding is invalid.', { bundleId: bundle.bundleId });
  if (!bundle.manifest || bundle.manifest.tenantId !== bundle.tenantId
      || bundle.manifest.evidenceId !== bundle.evidenceId
      || bundle.manifest.evidenceVersion !== bundle.evidenceVersion
      || bundle.manifest.recipientId !== bundle.recipientId) {
    throw new EvidenceIntegrityError('The assurance bundle manifest identity does not match its package.', { bundleId: bundle.bundleId });
  }
}

function verifyManifest(bundle) {
  const manifest = bundle.manifest;
  if (manifest.format !== MANIFEST_FORMAT || manifest.version !== 1) throw new EvidenceIntegrityError('The assurance bundle manifest format is invalid.');
  const { bundleDigest, ...unsigned } = manifest;
  if (hashValue(bundleDigest, 'bundleDigest') !== sha256(stableStringify(unsigned))) {
    throw new EvidenceIntegrityError('The assurance bundle manifest digest is invalid.', { bundleId: bundle.bundleId });
  }
  if (!manifest.sectionDigests || typeof manifest.sectionDigests !== 'object' || Array.isArray(manifest.sectionDigests)) {
    throw new EvidenceIntegrityError('The assurance bundle section digest map is invalid.');
  }
}

function verifySections(bundle) {
  if (!bundle.evidence || typeof bundle.evidence !== 'object' || Array.isArray(bundle.evidence)) {
    throw new EvidenceIntegrityError('The assurance bundle evidence sections are invalid.');
  }
  const expectedNames = Object.keys(bundle.manifest.sectionDigests).sort();
  const actualNames = Object.keys(bundle.evidence).sort();
  if (stableStringify(expectedNames) !== stableStringify(actualNames)) {
    throw new EvidenceIntegrityError('The assurance bundle section set does not match its manifest.');
  }
  for (const name of expectedNames) {
    const expected = hashValue(bundle.manifest.sectionDigests[name], `sectionDigests.${name}`);
    const actual = sha256(stableStringify(bundle.evidence[name]));
    if (expected !== actual) throw new EvidenceIntegrityError('An assurance bundle section digest is invalid.', { section: name });
  }
}

function verifyContent(bundle) {
  const content = bundle.evidence.content;
  if (!content || typeof content !== 'object' || Array.isArray(content)) throw new EvidenceIntegrityError('The assurance bundle content section is missing.');
  const bytes = canonicalBase64(content.contentBase64, 'contentBase64');
  if (!Number.isInteger(content.sizeBytes) || content.sizeBytes < 0 || bytes.length !== content.sizeBytes
      || sha256(bytes) !== hashValue(content.sha256, 'content.sha256')
      || content.sha256 !== bundle.manifest.contentSha256) {
    throw new EvidenceIntegrityError('The assurance bundle evidence content size or SHA-256 is invalid.');
  }
  if (bundle.evidence.version?.version !== bundle.evidenceVersion
      || bundle.evidence.version?.sha256 !== content.sha256
      || bundle.evidence.version?.sizeBytes !== content.sizeBytes) {
    throw new EvidenceIntegrityError('The assurance bundle immutable version metadata does not match its content.');
  }
}

function canonicalBase64(value, field) { const text = String(value ?? ''); const bytes = Buffer.from(text, 'base64'); if (!text || bytes.toString('base64') !== text) throw new EvidenceValidationError(`${field} must be canonical base64.`, { field }); return bytes; }
function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!/^[a-f0-9]{64}$/.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function keyIdentifier(value) { const text = String(value ?? ''); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,191}$/.test(text)) throw new EvidenceValidationError('recipientPublicKeyId is invalid.'); return text; }
function cleanToken(value) { const text = String(value ?? '').trim(); if (text.length < 20 || text.length > 500) throw new EvidenceValidationError('The claim token is invalid.'); return text; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

async function main(argv) {
  const [sealedPackagePath, recipientPrivateKeyPath, claimTokenPath] = argv;
  const result = await verifyAssuranceBundleFile({ sealedPackagePath, recipientPrivateKeyPath, claimTokenPath });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${JSON.stringify({ success: false, error: error.message, code: error.code ?? 'ASSURANCE_VERIFICATION_FAILED' })}\n`);
    process.exitCode = 1;
  });
}
