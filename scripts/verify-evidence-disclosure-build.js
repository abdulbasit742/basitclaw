import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceDisclosureStore.js',
  'src/evidence/evidenceDisclosureRegistry.js',
  'src/evidence/evidenceDisclosureHandler.js',
  'src/evidence/evidenceDisclosureServer.js',
  'src/types/evidence-disclosures.d.ts',
  'test/evidenceDisclosureStore.test.js',
  'test/evidenceDisclosureRegistry.test.js',
  'docs/evidence-disclosures.md'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceDisclosureStore.js', 'Disclosure store', [
  'basitclaw-evidence-disclosure-v1',
  'rsa-oaep-sha256',
  'aes-256-gcm',
  'ed25519',
  'recipientKeyFingerprint',
  'signingPublicKeyFingerprint',
  'encryptedMetadata: true',
  'generalEvidenceDownload: false',
  'EVIDENCE_DISCLOSURE_EXPIRED',
  'EVIDENCE_DISCLOSURE_REVOKED',
  'EVIDENCE_DISCLOSURE_DOWNLOAD_LIMIT',
  'missing_disclosure_metadata_keys',
  'missing_disclosure_signing_keys'
]);
await requireMarkers('src/evidence/evidenceDisclosureRegistry.js', 'Disclosure trust composition', [
  'DISCLOSE ${request.items.length} EVIDENCE VERSIONS TO',
  'verifiedForVersion',
  'verifyEvidencePreservation',
  'verifyEvidenceTimeAttestations',
  'missing_time_attestation_quorum',
  'tenant-sha256:',
  'REVOKE DISCLOSURE',
  'createEvidenceDisclosureRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceDisclosureHandler.js', 'Disclosure API', [
  '/api/workforce-audit/evidence-disclosures',
  '/download',
  '/verify',
  '/revoke',
  'evidence:export',
  'authFailure',
  'content-disposition',
  'decodeSegment'
]);
await requireMarkers('src/evidence/evidenceDisclosureServer.js', 'Disclosure runtime', [
  'createEvidenceTimeAttestationAwareApp',
  'evidenceDisclosureHandler',
  'require preservation and time-attestation controls',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Top-level runtime', [
  'createEvidenceDisclosureAwareApp'
]);
await requireMarkers('src/security/accessControl.js', 'Disclosure role permission', [
  'evidence:export'
]);
await requireMarkers('test/evidenceDisclosureStore.test.js', 'Disclosure cryptography tests', [
  'recipient-encrypted package',
  'valid Ed25519 manifest signature',
  'wrong recipient key',
  'tampered package ciphertext',
  'download limits, expiry and revocation'
]);
await requireMarkers('docs/evidence-disclosures.md', 'Disclosure runbook', [
  'recipient-bound',
  'RSA-OAEP-SHA-256',
  'AES-256-GCM',
  'Ed25519',
  'out-of-band',
  'cannot retract',
  'no general evidence download endpoint'
]);

console.log('Evidence disclosure build verification passed.');
