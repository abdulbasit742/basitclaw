import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceTimeAttestationStore.js',
  'src/evidence/evidenceTimeAttestationRegistry.js',
  'src/evidence/evidenceTimeAttestationHandler.js',
  'src/evidence/evidenceTimeAttestationServer.js',
  'src/types/evidence-time-attestations.d.ts',
  'test/evidenceTimeAttestationStore.test.js',
  'docs/evidence-time-attestations.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceTimeAttestationStore.js', 'Time-attestation store', [
  'ed25519', 'rsa-pss-sha256', 'RSA_PKCS1_PSS_PADDING',
  'basitclaw-evidence-time-attestation-v1', 'nonce_replay',
  'timestamp_before_archive', 'timestamp_delay_exceeded',
  'minimumProviders', 'distinctProviders', 'quorumSatisfied',
  'encryptEvidenceJson', 'previousHash', 'EVIDENCE_TIME_ATTESTATION_REQUIRED'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationRegistry.js', 'Time-attestation composition', [
  'receiptSha256', 'objectEnvelopeSha256', 'missingQuorum',
  'quorumForArchive', 'requiredForDisposition',
  'createEvidenceTimeAttestationRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationHandler.js', 'Time-attestation API', [
  '/api/workforce-audit/evidence-notary/attestations',
  '/notary-challenge', 'ATTESTATIONS_ROUTE', 'VERIFY_ROUTE',
  'Signature realm', 'authFailure', 'EVIDENCE_TIME_ATTESTATION_BUSY'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationServer.js', 'Time-attestation server', [
  'createEvidencePreservationAwareApp', 'evidenceTimeAttestationHandler', 'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Time-attestation runtime', [
  'createEvidenceTimeAttestationAwareApp'
]);
await requireMarkers('docs/evidence-time-attestations.md', 'Time-attestation runbook', [
  'RFC 3161', 'court-certified', 'basitclaw-evidence-time-attestation-v1',
  'distinct authority providers', 'EVIDENCE_TIME_ATTESTATION_REQUIRED',
  'does not replace legal review'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production notary configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUIRED_FOR_DISPOSITION=true',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_MINIMUM_PROVIDERS=2',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEYS='
]);

console.log('Independent evidence time-attestation build verification passed.');
