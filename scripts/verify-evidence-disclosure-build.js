import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceDisclosurePackageStore.js',
  'src/evidence/evidenceDisclosurePackageRegistry.js',
  'src/evidence/evidenceDisclosurePackageHandler.js',
  'src/evidence/evidenceDisclosurePackageServer.js',
  'src/types/evidence-disclosure-packages.d.ts',
  'scripts/verify-evidence-disclosure-package.js',
  'test/evidenceDisclosurePackageStore.test.js',
  'test/evidenceDisclosurePackageHttp.test.js',
  'docs/evidence-disclosure-packages.md',
  'config/evidence-disclosure.development.env.example',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceDisclosurePackageStore.js', 'Disclosure package store', [
  'basitclaw-evidence-disclosure-package',
  'basitclaw-evidence-disclosure-receipt-index',
  'ed25519', 'rsa-oaep-sha256+aes-256-gcm',
  'metadataOnlyByDefault: true',
  'configuredRecipients',
  'packageSha256', 'manifestSha256',
  'previousHash', 'verifyEvidenceDisclosurePackage',
  'missing_disclosure_configuration'
]);
await requireMarkers('src/evidence/evidenceDisclosurePackageRegistry.js', 'Disclosure package composition', [
  'confirmation must be exactly EXPORT',
  'metadataOnlyDefault: true',
  'arbitraryRecipientKeysAccepted: false',
  'plaintextPackagePersisted: false',
  'revokedOrSupersededAttestationsExcludedFromOperationalQuorum: true',
  'unsupported field',
  'screeningReports', 'externalScanAttestations',
  'preservationReceipts', 'timeAttestationGovernance',
  'effectiveArchiveVerification',
  'registry.readContent',
  'createEvidenceTimeAttestationGovernanceRegistryFromEnvironment',
  'createEvidenceDisclosurePackageRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceDisclosurePackageHandler.js', 'Disclosure package API', [
  '/api/workforce-audit/evidence-disclosure/status',
  '/disclosure-packages',
  'evidence:export',
  'sensitive',
  'decodeSegment',
  'EVIDENCE_DISCLOSURE_BUSY'
]);
await requireMarkers('src/evidence/evidenceDisclosurePackageServer.js', 'Disclosure package server', [
  'createEvidenceTimeAttestationGovernanceAwareApp',
  'createExportAuthenticationGateway',
  "existing.includes('evidence:preserve')",
  "'evidence:export'",
  'evidenceTimeAttestationGovernanceHandler',
  'evidenceDisclosurePackageHandler',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Disclosure-aware runtime', [
  'createEvidenceDisclosurePackageAwareApp'
]);
await requireMarkers('scripts/verify-evidence-disclosure-package.js', 'Offline disclosure verifier', [
  'verifyEvidenceDisclosurePackage',
  'privateDecrypt',
  'RSA_PKCS1_OAEP_PADDING',
  'createDecipheriv',
  'contentDecryptionPerformed',
  'ciphertext digest is invalid'
]);
await requireMarkers('test/evidenceDisclosurePackageStore.test.js', 'Disclosure package regressions', [
  'only encrypted receipts persist',
  'decrypt only with the configured recipient',
  'package tampering',
  'Metadata package for audit committee',
  'operationally acceptable notary decisions'
]);
await requireMarkers('docs/evidence-disclosure-packages.md', 'Disclosure package runbook', [
  'metadata-only',
  'EXPORT EVD-',
  'pre-approved recipient',
  'offline verifier',
  'does not establish legal admissibility',
  'revoked or superseded',
  'never stored'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production disclosure configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS=',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_SIGNING_KEYS=',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE=shared-file',
  'evidence:export'
]);

console.log('Selective evidence disclosure package build verification passed.');
