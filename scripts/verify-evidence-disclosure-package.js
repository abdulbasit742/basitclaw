import {
  constants,
  createDecipheriv,
  createPrivateKey,
  privateDecrypt
} from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  EvidenceDisclosureIntegrityError,
  verifyEvidenceDisclosurePackage
} from '../src/evidence/evidenceDisclosurePackageStore.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const SEALED_CONTENT_FORMAT = 'basitclaw-evidence-disclosure-sealed-content';

export async function verifyDisclosurePackageFile({ packagePath, publicKeyPath, privateKeyPath = null } = {}) {
  if (!packagePath || !publicKeyPath) throw new TypeError('packagePath and publicKeyPath are required.');
  const disclosurePackage = JSON.parse(await readFile(packagePath, 'utf8'));
  const publicKeyPem = await readFile(publicKeyPath, 'utf8');
  const signature = verifyEvidenceDisclosurePackage(disclosurePackage, publicKeyPem);
  const contents = privateKeyPath
    ? decryptSealedContents(disclosurePackage, await readFile(privateKeyPath, 'utf8'))
    : [];
  return {
    ...signature,
    contentDecryptionPerformed: Boolean(privateKeyPath),
    decryptedContents: contents
  };
}

export function decryptSealedContents(disclosurePackage, privateKeyPem) {
  const privateKey = createPrivateKey(String(privateKeyPem ?? ''));
  if (privateKey.asymmetricKeyType !== 'rsa' || (privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
    throw new EvidenceDisclosureIntegrityError('The disclosure recipient private key must be RSA with at least 2048 bits.');
  }
  const rows = Array.isArray(disclosurePackage?.sealedContents) ? disclosurePackage.sealedContents : [];
  return rows.map((sealed) => decryptSealedContent(disclosurePackage, sealed, privateKey));
}

function decryptSealedContent(disclosurePackage, sealed, privateKey) {
  if (!sealed || sealed.format !== SEALED_CONTENT_FORMAT || sealed.version !== 1
      || sealed.algorithm !== 'rsa-oaep-sha256+aes-256-gcm') {
    throw new EvidenceDisclosureIntegrityError('A sealed disclosure content record has an invalid format.');
  }
  const ciphertext = canonicalBase64(sealed.ciphertext, 'ciphertext');
  if (sha256(ciphertext) !== sealed.ciphertextSha256) {
    throw new EvidenceDisclosureIntegrityError('A sealed disclosure ciphertext digest is invalid.', { evidenceVersion: sealed.evidenceVersion });
  }
  let key;
  try {
    key = privateDecrypt({
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    }, canonicalBase64(sealed.wrappedKey, 'wrappedKey'));
  } catch (error) {
    throw new EvidenceDisclosureIntegrityError('The sealed disclosure content key could not be unwrapped.', { evidenceVersion: sealed.evidenceVersion }, error);
  }
  let plaintext;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, canonicalBase64(sealed.iv, 'iv'));
    decipher.setAAD(canonicalBase64(sealed.aad, 'aad'));
    decipher.setAuthTag(canonicalBase64(sealed.tag, 'tag'));
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    throw new EvidenceDisclosureIntegrityError('The sealed disclosure content authentication failed.', { evidenceVersion: sealed.evidenceVersion }, error);
  }
  let payload;
  try { payload = JSON.parse(plaintext.toString('utf8')); }
  catch (error) { throw new EvidenceDisclosureIntegrityError('The sealed disclosure content payload is invalid JSON.', {}, error); }
  const content = canonicalBase64(payload.contentBase64, 'contentBase64');
  if (payload.format !== SEALED_CONTENT_FORMAT || payload.version !== 1
      || payload.packageId !== disclosurePackage.packageId
      || payload.evidenceId !== disclosurePackage.evidenceId
      || payload.evidenceVersion !== sealed.evidenceVersion
      || payload.contentSha256 !== sealed.contentSha256
      || payload.sizeBytes !== sealed.sizeBytes
      || content.length !== payload.sizeBytes
      || sha256(content) !== payload.contentSha256) {
    throw new EvidenceDisclosureIntegrityError('The sealed disclosure content identity or checksum is invalid.', {
      evidenceVersion: sealed.evidenceVersion
    });
  }
  return {
    evidenceVersion: payload.evidenceVersion,
    filename: payload.filename,
    mediaType: payload.mediaType,
    contentSha256: payload.contentSha256,
    sizeBytes: payload.sizeBytes,
    contentBase64: content.toString('base64')
  };
}

function canonicalBase64(value, field) {
  const text = String(value ?? '');
  const bytes = Buffer.from(text, 'base64');
  if (!text || bytes.toString('base64') !== text) throw new EvidenceDisclosureIntegrityError(`${field} must be canonical base64.`);
  return bytes;
}

async function main(argv) {
  const [packagePath, publicKeyPath, privateKeyPath] = argv;
  const result = await verifyDisclosurePackageFile({ packagePath, publicKeyPath, privateKeyPath });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${JSON.stringify({ success: false, error: error.message, code: error.code ?? 'VERIFICATION_FAILED' })}\n`);
    process.exitCode = 1;
  });
}
