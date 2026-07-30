import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceTimeAuthorityPolicyStore.js',
  'src/evidence/evidenceTimeAttestationRegistry.js',
  'src/evidence/evidenceTimeAttestationGovernanceRegistry.js',
  'src/types/evidence-time-authority-policy.d.ts',
  'test/evidenceTimeAuthorityPolicyStore.test.js',
  'docs/evidence-time-authority-policy.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceTimeAuthorityPolicyStore.js', 'Authority key policy store', [
  'validFrom', 'validUntil', 'allowedPolicyIds',
  'key_not_yet_valid', 'key_expired_at_attestation', 'policy_not_allowed',
  'cryptographicQuorumSatisfied', 'policyCompliantDistinctProviders',
  'maximumAttestationsPerArchive', 'keyPolicyEnforced: true',
  'authenticateSubmission', 'signature_invalid', 'combinedStatus',
  'EVIDENCE_TIME_AUTHORITY_POLICY_NOT_TRUSTED'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationRegistry.js', 'Authority policy composition', [
  'createEvidenceTimeAuthorityPolicyStoreFromEnvironment',
  'baseTimeAttestations',
  'timeAttestations = createEvidenceTimeAuthorityPolicyStoreFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationGovernanceRegistry.js', 'Policy and governance composition', [
  'authorityPolicyEnforced',
  'policyRejectedAttestations',
  "attestation.authorityPolicy?.trusted !== false",
  'operationalQuorumSatisfied'
]);
await requireMarkers('test/evidenceTimeAuthorityPolicyStore.test.js', 'Authority policy safeguards', [
  'not-yet-valid, expired and unapproved-policy',
  'cryptographic quorum is recalculated from policy-compliant distinct providers',
  'required policy health fails closed',
  'optional policy-provider shortfall surfaces attention',
  'operational governance cannot restore an attestation rejected by authority key policy'
]);
await requireMarkers('docs/evidence-time-authority-policy.md', 'Authority policy runbook', [
  'Separate responsibilities',
  'allowedPolicyIds',
  'append-only revocation and supersession journal',
  'cannot restore an expired or disallowed key',
  'EVIDENCE_TIME_AUTHORITY_POLICY_NOT_TRUSTED'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production authority policy configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEY_EXPIRY_WARNING_DAYS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_MAX_ATTESTATIONS_PER_ARCHIVE=',
  'allowedPolicyIds', 'validFrom', 'validUntil',
  'Use the append-only governance journal below for revocation or compromise'
]);

console.log('Evidence time-authority key policy build verification passed.');
