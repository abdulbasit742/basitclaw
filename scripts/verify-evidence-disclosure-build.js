import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceDisclosureStore.js',
  'src/evidence/evidenceDisclosureRegistry.js',
  'src/evidence/evidenceDisclosureHandler.js',
  'src/evidence/evidenceDisclosureServer.js',
  'src/types/evidence-disclosures.d.ts',
  'test/evidenceDisclosureStore.test.js',
  'test/evidenceDisclosureHttp.test.js',
  'docs/evidence-disclosures.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceDisclosureStore.js', 'Disclosure store', [
  'basitclaw-evidence-disclosure-index',
  'basitclaw-evidence-disclosure-package',
  'basitclaw-evidence-disclosure-manifest',
  'RSA-OAEP-SHA256+A256GCM',
  'createCipheriv',
  'publicEncrypt',
  'requester cannot approve',
  'duplicate_approval',
  'recipientKeyFingerprint',
  'created && !committed',
  'verifyEventChain',
  'recipientSealedPackages: true'
]);
await requireMarkers('src/evidence/evidenceDisclosureRegistry.js', 'Disclosure composition', [
  'preservation_required',
  'time_attestation_required',
  'verifiedForVersion',
  'quorumForArchive',
  'createEvidenceDisclosureRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceDisclosureHandler.js', 'Disclosure API', [
  '/api/workforce-audit/evidence-disclosures',
  'evidence:disclose:approve',
  'authFailure',
  'EVIDENCE_DISCLOSURE_BUSY',
  'decodeSegment',
  'sealed_package_read'
]);
await requireMarkers('src/evidence/evidenceDisclosureServer.js', 'Disclosure runtime', [
  'createEvidenceTimeAttestationAwareApp',
  'createDisclosureAuthenticationGateway',
  "'backup:restore'",
  "'governance:read'",
  'evidenceDisclosureHandler',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Outer runtime', [
  'createEvidenceDisclosureAwareApp'
]);
await requireMarkers('test/evidenceDisclosureStore.test.js', 'Disclosure cryptographic tests', [
  'only the recipient private key decrypts',
  'contain no operational plaintext',
  'requester separation and two distinct approvals',
  'sealed package tampering'
]);
await requireMarkers('test/evidenceDisclosureHttp.test.js', 'Disclosure HTTP tests', [
  'separate permissions',
  'invalid percent encoding',
  'closeAllConnections',
  'recipient-sealed envelope'
]);
await requireMarkers('docs/evidence-disclosures.md', 'Disclosure runbook', [
  'does not email evidence',
  'Requester/approver separation',
  'RSA-OAEP',
  'AES-256-GCM',
  'recipient private keys',
  'REVOKE DISCLOSURE'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production disclosure configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MINIMUM_APPROVERS=2',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_PRESERVATION=true',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_TIME_ATTESTATION=true',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS='
]);

console.log('Governed evidence disclosure build verification passed.');
