import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceAssuranceBundleStore.js',
  'src/evidence/evidenceAssuranceBundleRegistry.js',
  'src/evidence/evidenceAssuranceBundleHandler.js',
  'src/evidence/evidenceAssuranceBundleServer.js',
  'test/evidenceAssuranceBundleStore.test.js',
  'test/evidenceAssuranceBundleRegistry.test.js',
  'test/evidenceAssuranceBundleHttp.test.js',
  'test/evidenceAssuranceBundleServer.test.js',
  'docs/evidence-assurance-bundles.md',
  'src/types/evidence-assurance-bundles.d.ts',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
}

await requireMarkers('src/evidence/evidenceAssuranceBundleStore.js', 'Assurance bundle store', [
  'RSA-OAEP-SHA256+A256GCM', 'recipientEncryptedPackages: true',
  'plaintextPersistence: false', 'arbitraryOutboundEgress: false',
  'registerReplay', 'maximumClaimBytes', 'created && !committed',
  'state !== \'expired\'', 'Dedicated assurance bundle encryption keys are required'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleRegistry.js', 'Assurance bundle registry', [
  'createEvidenceTimeAttestationGovernanceRegistryFromEnvironment',
  'EXPORT ${item.evidenceId} V${version} TO ${recipientId}',
  'custodyEvents', 'preservationReceipts', 'timeAttestations',
  'timeAttestationVerifications', 'operationallyAcceptable',
  'sectionDigests', 'redactItem'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleHandler.js', 'Assurance bundle APIs', [
  '/api/workforce-audit/assurance-bundles/status', '/assurance-bundles',
  '/api/workforce-audit/assurance-recipient/bundles/claim',
  'evidence:export', 'HMAC realm', 'decodeSegment'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleServer.js', 'Assurance bundle server', [
  'createEvidenceTimeAttestationGovernanceAwareApp',
  'evidenceTimeAttestationGovernanceHandler',
  'evidenceAssuranceBundleHandler',
  'require enabled encrypted evidence custody'
]);
await requireMarkers('src/evidenceRuntime.js', 'Assurance bundle runtime', ['createEvidenceAssuranceBundleAwareApp']);
await requireMarkers('src/security/accessControl.js', 'Assurance bundle permission', ['evidence:export']);
await requireMarkers('docs/evidence-assurance-bundles.md', 'Assurance bundle runbook', [
  'Pass 21', 'never sends bundles to arbitrary URLs', 'recipient private key',
  'EXPORT EVD-', 'RSA-OAEP-SHA256', 'one-time claim token',
  'operational notary-governance decisions'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Assurance bundle production configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE=shared-file',
  'WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MODE=pull',
  'WORKFORCE_AUDIT_ASSURANCE_BUNDLE_REQUIRED=true',
  'WORKFORCE_AUDIT_ASSURANCE_BUNDLE_KEYS=',
  'WORKFORCE_AUDIT_ASSURANCE_RECIPIENTS=',
  'No outbound URL is configured'
]);
console.log('Evidence assurance bundle build verification passed.');
