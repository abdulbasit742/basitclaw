import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceDisclosureStore.js',
  'src/evidence/evidenceDisclosureRegistry.js',
  'src/evidence/evidenceDisclosureHandler.js',
  'src/evidence/evidenceDisclosureServer.js',
  'test/evidenceDisclosureStore.test.js',
  'test/evidenceDisclosureHttp.test.js',
  'docs/evidence-disclosure.md',
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
  'basitclaw-evidence-disclosure-v1',
  'basitclaw-recipient-sealed-evidence-v1',
  'aes-256-gcm+rsa-oaep-sha256',
  'approvalQuorum',
  'requester cannot approve',
  'allowedZones',
  'nonce_replay',
  'claimToken',
  'disclosure.acknowledged',
  'previousHash',
  'encryptEvidenceJson',
  'EVIDENCE_DISCLOSURE_AUTHENTICATION_FAILED'
]);
await requireMarkers('src/evidence/evidenceDisclosureRegistry.js', 'Disclosure composition', [
  'immutable preservation',
  'time-attestation quorum',
  'assertDisclosurePrerequisites',
  'requestEvidenceDisclosure',
  'approveEvidenceDisclosure',
  'createEvidenceDisclosureRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidenceDisclosureHandler.js', 'Disclosure API', [
  '/api/workforce-audit/evidence-disclosures/status',
  '/api/workforce-audit/evidence-disclosure-recipient/claim',
  'APPROVE DISCLOSURE',
  'REVOKE DISCLOSURE',
  'HMAC realm',
  'decodeSegment',
  'authFailure'
]);
await requireMarkers('src/evidence/evidenceDisclosureServer.js', 'Disclosure server', [
  'createEvidenceTimeAttestationAwareApp',
  'evidenceDisclosureHandler',
  'requires enabled preservation and independent time attestations',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Disclosure runtime', [
  'createEvidenceDisclosureAwareApp'
]);
await requireMarkers('test/evidenceDisclosureStore.test.js', 'Disclosure safeguards', [
  'requires two distinct approvals',
  'decrypts only with the recipient private key',
  'rejects recipient replay',
  'enforces residency zones',
  'acknowledgement removes sealed package bytes'
]);
await requireMarkers('test/evidenceDisclosureHttp.test.js', 'Disclosure HTTP safeguards', [
  'governance request and approval flow',
  'recipient pull and acknowledgement flow',
  'malformed encoded disclosure IDs',
  'closeAllConnections'
]);
await requireMarkers('docs/evidence-disclosure.md', 'Disclosure runbook', [
  'Passes 20–27',
  'two distinct human approvers',
  'RSA-OAEP-SHA-256',
  'data residency',
  'never stores plaintext evidence in the disclosure queue',
  'does not automatically release quarantined evidence'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production disclosure configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_APPROVAL_QUORUM=2',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_RECIPIENTS=',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_TENANT_ZONES=',
  'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_KEYS='
]);
await requireMarkers('package.json', 'Disclosure release version', [
  '"version": "0.27.0"',
  'verify-evidence-disclosure-build.js'
]);

console.log('Governed evidence disclosure build verification passed.');
