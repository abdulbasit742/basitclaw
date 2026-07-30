import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceTimeAttestationRequestOutbox.js',
  'src/evidence/evidenceTimeAttestationRequestRegistry.js',
  'src/evidence/evidenceTimeAttestationRequestHandler.js',
  'src/evidence/evidenceTimeAttestationRequestServer.js',
  'src/types/evidence-notary-requests.d.ts',
  'test/evidenceTimeAttestationRequestOutbox.test.js',
  'test/evidenceTimeAttestationRequestHttp.test.js',
  'docs/evidence-notary-requests.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceTimeAttestationRequestOutbox.js', 'Notary request outbox', [
  'basitclaw-evidence-notary-request-index',
  'basitclaw-evidence-notary-request-auth-v1',
  'createEvidenceTimeAttestationRequestOutboxFromEnvironment',
  'providerPartitioned: true',
  'plaintextEvidenceQueued: false',
  'evidenceBytesQueued: false',
  'arbitraryOutboundUrls: false',
  'requestReplayProtected: true',
  'transitionHashChain: true',
  'claim_recovered',
  'attestation_timeout',
  'canonicalEvidenceNotaryRequest',
  'completeFromAttestation'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationRequestRegistry.js', 'Notary request composition', [
  'createEvidenceTimeAttestationGovernanceRegistryFromEnvironment',
  'REQUEST NOTARY',
  'REQUEUE NOTARY',
  'alreadyAttested',
  'requestCompletion',
  'evidence:notarize'
].filter((marker) => marker !== 'evidence:notarize'));
await requireMarkers('src/evidence/evidenceTimeAttestationRequestHandler.js', 'Notary request API', [
  '/api/workforce-audit/evidence-notary/requests/claim',
  '/notary-requests',
  'evidence:notarize',
  'Signature realm',
  'authFailure',
  'decodeSegment',
  'EVIDENCE_NOTARY_REQUEST_BUSY'
]);
await requireMarkers('src/evidence/evidenceTimeAttestationRequestServer.js', 'Notary request runtime', [
  'createEvidenceTimeAttestationGovernanceAwareApp',
  'evidenceTimeAttestationRequestHandler',
  'requires enabled time attestations',
  'requires enabled immutable preservation'
]);
await requireMarkers('src/evidenceRuntime.js', 'Runtime startup', [
  'createEvidenceTimeAttestationRequestAwareApp'
]);
await requireMarkers('src/security/accessControl.js', 'Notary request access control', [
  'evidence:notarize'
]);
await requireMarkers('test/evidenceTimeAttestationRequestOutbox.test.js', 'Notary request regressions', [
  'authority claims an encrypted provider-partitioned challenge',
  'signed request replay is rejected',
  'matching attestation completes its deterministic request',
  'expired claims recover and terminal failures can be requeued',
  'transition chain tampering fails closed'
]);
await requireMarkers('test/evidenceTimeAttestationRequestHttp.test.js', 'Notary request HTTP regressions', [
  'manager queues and authority claims a notary request',
  'invalid authority signature is rejected',
  'malformed encoded request IDs return 400',
  'closeAllConnections'
]);
await requireMarkers('docs/evidence-notary-requests.md', 'Notary request runbook', [
  'no authority private key',
  'never contains evidence bytes',
  'basitclaw-evidence-notary-request-auth-v1',
  'attestation_timeout',
  'REQUEST NOTARY',
  'REQUEUE NOTARY'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production notary request configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_MODE=pull',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_REQUIRED=true',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_KEYS=',
  'WORKFORCE_AUDIT_EVIDENCE_NOTARY_REQUEST_PRIMARY_KEY_ID='
]);

console.log('Evidence-notary request build verification passed.');
