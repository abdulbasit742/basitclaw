import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceAssuranceGovernanceStore.js',
  'src/evidence/evidenceAssuranceGovernanceRegistry.js',
  'src/evidence/evidenceAssuranceGovernanceHandler.js',
  'src/evidence/evidenceAssuranceGovernanceServer.js',
  'src/types/evidence-assurance-governance.d.ts',
  'test/evidenceAssuranceGovernanceStore.test.js',
  'test/evidenceAssuranceGovernanceRegistry.test.js',
  'test/evidenceAssuranceGovernanceHttp.test.js',
  'test/evidenceAssuranceGovernanceServer.test.js',
  'docs/evidence-assurance-governance.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceAssuranceGovernanceStore.js', 'Assurance governance store', [
  'basitclaw-assurance-governance-request',
  'basitclaw-assurance-governance-bundle-index',
  'The assurance requester cannot approve their own request',
  'approvalQuorum',
  'allowedPurposeCodes',
  'allowedLegalBases',
  'allowedResidencyZones',
  'recipient policy has expired',
  'delivery_suppressed',
  'cannot be retroactively revoked',
  'encryptEvidenceJson',
  'previousHash',
  'bundleIndexEncrypted: true',
  'missing_governance_keys',
  'EVIDENCE_ASSURANCE_GOVERNANCE_STORE_UNAVAILABLE'
]);
await requireMarkers('src/evidence/evidenceAssuranceBundleRegistry.js', 'Governed bundle manifest', [
  'governanceRequestId',
  'purposeCode',
  'legalBasis',
  'residencyZone',
  'disclosurePolicy'
]);
await requireMarkers('src/evidence/evidenceAssuranceGovernanceRegistry.js', 'Assurance governance composition', [
  'EVIDENCE_ASSURANCE_GOVERNANCE_REQUIRED',
  'REQUEST EXPORT',
  'createBaseBundle',
  'readyToSeal',
  'deliveryAllowed',
  'recordSuppressedDelivery',
  'markDelivered',
  'claimed or delivered assurance bundle cannot be revoked'
]);
await requireMarkers('src/evidence/evidenceAssuranceGovernanceHandler.js', 'Assurance governance API', [
  '/api/workforce-audit/assurance-governance/status',
  '/assurance-requests',
  'APPROVE ASSURANCE',
  'SEAL ASSURANCE',
  'REJECT ASSURANCE',
  'REVOKE ASSURANCE',
  'privileged:revoke',
  'authFailure',
  'decodeSegment'
]);
await requireMarkers('src/evidence/evidenceAssuranceGovernanceServer.js', 'Assurance governance server', [
  'createEvidenceAssuranceBundleAwareApp',
  'assuranceGovernanceHandler',
  'requires enabled assurance bundle delivery',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Assurance governance runtime', [
  'createEvidenceAssuranceGovernanceAwareApp'
]);
await requireMarkers('test/evidenceAssuranceGovernanceStore.test.js', 'Assurance governance safeguards', [
  'enforces recipient purpose, legal-basis and residency policy',
  'requires requester separation and two distinct approvers',
  'revocation suppresses recipient delivery',
  'expired pending requests are persisted'
]);
await requireMarkers('test/evidenceAssuranceGovernanceRegistry.test.js', 'Assurance governance composition safeguards', [
  'Pass 21 sealing occurs only after quorum',
  'revoked or unlinked claimed bundles are removed'
]);
await requireMarkers('test/evidenceAssuranceGovernanceHttp.test.js', 'Assurance governance HTTP safeguards', [
  'original assurance-bundle POST now creates a governed request',
  'approval and revocation require exact governed confirmations',
  'invalid percent encoding',
  'closeAllConnections'
]);
await requireMarkers('docs/evidence-assurance-governance.md', 'Assurance governance runbook', [
  'Passes 22–27',
  'requester cannot approve',
  'legal basis',
  'residency zone',
  'recipient response',
  'does not itself establish legal authority'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production assurance governance configuration', [
  'WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_MODE=shared-file',
  'WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_REQUIRED=true',
  'WORKFORCE_AUDIT_ASSURANCE_APPROVAL_QUORUM=2',
  'WORKFORCE_AUDIT_ASSURANCE_RECIPIENT_POLICIES=',
  'WORKFORCE_AUDIT_ASSURANCE_GOVERNANCE_KEYS='
]);
await requireMarkers('package.json', 'Assurance governance release version', [
  '"version": "0.27.0"',
  'verify-evidence-assurance-bundle-build.js',
  'verify-evidence-assurance-governance-build.js'
]);

console.log('Assurance export governance build verification passed.');
