import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceTimeAttestationGovernanceStore.js',
  'src/evidence/evidenceTimeAttestationGovernanceRegistry.js',
  'src/evidence/evidenceTimeAttestationGovernanceHandler.js',
  'src/evidence/evidenceTimeAttestationGovernanceServer.js',
  'src/types/evidence-time-attestation-governance.d.ts',
  'test/evidenceTimeAttestationGovernance.test.js',
  'docs/evidence-time-attestation-governance.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceTimeAttestationGovernanceStore.js', 'Notary governance journal', [
  'basitclaw-evidence-time-attestation-governance-index',
  'attestation_revoked', 'provider_revoked', 'key_revoked', 'attestation_superseded',
  'authority_compromise', 'key_compromise', 'retroactive', 'effectiveAt',
  'cryptographicallyValid', 'operationallyAcceptable',
  'encryptEvidenceJson', 'timingSafeEqual', 'previousHash', 'signedEvents: true',
  'missing_governance_encryption_keys', 'missing_governance_signing_secrets',
  'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_REQUIRED'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationGovernanceRegistry.js', 'Effective notary policy', [
  'REVOKE ATTESTATION', 'SUPERSEDE ATTESTATION', 'REVOKE NOTARY PROVIDER', 'REVOKE NOTARY KEY',
  'currentOperationalPosture', 'operationalQuorumSatisfied', 'missingPreservations',
  'missingOperationalQuorum', 'EvidenceTimeAttestationGovernanceRequiredError',
  'createEvidenceTimeAttestationGovernanceRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationGovernanceHandler.js', 'Notary governance API', [
  '/api/workforce-audit/evidence-notary/governance/status',
  '/api/workforce-audit/evidence-notary/governance/events',
  '/api/workforce-audit/evidence-notary/governance/verify',
  'evidence:notary-govern', 'authFailure', 'unsupported field',
  'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_BUSY'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationGovernanceServer.js', 'Notary governance runtime', [
  'createEvidenceTimeAttestationAwareApp',
  'notaryGovernanceAuthenticationGateway',
  "permission === 'evidence:notary-govern' ? 'evidence:preserve'",
  'evidenceTimeAttestationGovernanceHandler',
  'resilienceScheduler'
]);
await requireMarkers('src/regulatory/regulatoryCaseServer.js', 'Composed regulatory runtime', [
  'createEvidenceTimeAttestationGovernanceAwareApp',
  'evidenceTimeAttestationGovernanceHandler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Outermost evidence runtime', [
  'createRegulatoryCaseAwareApp'
]);
await requireMarkers('test/evidenceTimeAttestationGovernance.test.js', 'Notary governance regressions', [
  'prospective provider revocation preserves earlier proof',
  'retroactive key compromise excludes historical attestations',
  'supersession marks only the original attestation',
  'recalculates quorum and blocks disposition',
  'manager-only preservation permission'
]);
await requireMarkers('docs/evidence-time-attestation-governance.md', 'Notary governance runbook', [
  'Cryptographically valid', 'Operationally acceptable',
  'No undo or deletion', 'retroactive: true',
  'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_REQUIRED',
  'does not establish an authority'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production notary governance configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_REQUIRED_FOR_DISPOSITION=true',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_KEYS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_SIGNING_SECRETS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_GOVERNANCE_MAX_EVENTS=100000'
]);

console.log('Evidence time-attestation governance build verification passed.');
