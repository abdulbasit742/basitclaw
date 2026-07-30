import { createPublicKey, verify as verifyAsymmetric } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { sha256, strictBase64 } from '../src/evidence/evidenceCrypto.js';
import { EvidenceIntegrityError, EvidenceValidationError } from '../src/evidence/evidenceRegistry.js';

const RECEIPT_FORMAT = 'basitclaw-assurance-acceptance-receipt';

export async function verifyAssuranceAcceptanceReceiptFile({ receiptPath, signingPublicKeyPath, tenantId } = {}) {
  if (!receiptPath || !signingPublicKeyPath || !tenantId) throw new TypeError('receiptPath, signingPublicKeyPath and tenantId are required.');
  return verifyAssuranceAcceptanceReceipt(
    JSON.parse(await readFile(receiptPath, 'utf8')),
    await readFile(signingPublicKeyPath, 'utf8'),
    tenantId
  );
}

export function verifyAssuranceAcceptanceReceipt(receipt, signingPublicKeyPem, tenantId) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)
      || receipt.format !== RECEIPT_FORMAT || receipt.version !== 1
      || !/^AAR-[a-f0-9]{32}$/.test(String(receipt.acceptanceId ?? ''))
      || !/^ASB-[a-f0-9]{32}$/.test(String(receipt.bundleId ?? ''))) {
    throw new EvidenceValidationError('The assurance acceptance receipt format is invalid.');
  }
  const tenant = safeIdentifier(tenantId, 'tenantId');
  const publicKey = createPublicKey(String(signingPublicKeyPem ?? ''));
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new EvidenceValidationError('The assurance acceptance signing public key must be Ed25519.');
  const fingerprint = sha256(publicKey.export({ type: 'spki', format: 'der' }));
  if (receipt.signingAlgorithm !== 'ed25519' || receipt.signingKeyFingerprint !== fingerprint) {
    throw new EvidenceIntegrityError('The assurance acceptance signing identity does not match the trusted public key.');
  }
  const { signingAlgorithm, signingKeyId, signingKeyFingerprint, signature, ...publicBody } = receipt;
  const body = { ...publicBody, tenantId: tenant };
  let signatureBytes;
  try { signatureBytes = strictBase64(signature, 'acceptance receipt signature'); }
  catch (error) { throw new EvidenceIntegrityError('The assurance acceptance receipt signature is malformed.', {}, error); }
  if (!verifyAsymmetric(null, Buffer.from(stableStringify(body)), publicKey, signatureBytes)) {
    throw new EvidenceIntegrityError('The assurance acceptance receipt signature verification failed.', { acceptanceId: receipt.acceptanceId });
  }
  for (const field of ['packageSha256', 'plaintextSha256', 'bundleDigest', 'sectionDigestsSha256', 'contentSha256', 'recipientRequestBodySha256']) {
    hashValue(receipt[field], field);
  }
  if (receipt.verificationOutcome !== 'verified') throw new EvidenceIntegrityError('The assurance acceptance receipt does not record a verified outcome.');
  return {
    valid: true,
    acceptanceId: receipt.acceptanceId,
    bundleId: receipt.bundleId,
    tenantId: tenant,
    evidenceId: receipt.evidenceId,
    evidenceVersion: receipt.evidenceVersion,
    recipientId: receipt.recipientId,
    packageSha256: receipt.packageSha256,
    plaintextSha256: receipt.plaintextSha256,
    bundleDigest: receipt.bundleDigest,
    verifiedAt: receipt.verifiedAt,
    acknowledgedAt: receipt.acknowledgedAt,
    signingKeyId,
    signingKeyFingerprint
  };
}

function hashValue(value, field) { const text = String(value ?? '').toLowerCase(); if (!/^[a-f0-9]{64}$/.test(text)) throw new EvidenceValidationError(`${field} must be a SHA-256 digest.`, { field }); return text; }
function safeIdentifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

async function main(argv) {
  const [receiptPath, signingPublicKeyPath, tenantId] = argv;
  const result = await verifyAssuranceAcceptanceReceiptFile({ receiptPath, signingPublicKeyPath, tenantId });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${JSON.stringify({ success: false, error: error.message, code: error.code ?? 'ACCEPTANCE_RECEIPT_VERIFICATION_FAILED' })}\n`);
    process.exitCode = 1;
  });
}
