import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/regulatory/regulatoryCaseStore.js',
  'src/regulatory/regulatoryCaseHandler.js',
  'src/regulatory/regulatoryCaseServer.js',
  'src/types/regulatory-cases.d.ts',
  'test/regulatoryCaseStore.test.js',
  'test/regulatoryCaseHttp.test.js',
  'test/regulatoryCaseServer.test.js',
  'docs/regulatory-case-register.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/regulatory/regulatoryCaseStore.js', 'Regulatory case store', [
  'basitclaw-regulatory-case-register',
  'regulator_request', 'external_audit', 'legal_request', 'certification_review',
  'SUBMIT RESPONSE', 'APPROVE RESPONSE',
  "target === 'closed' ? 'CLOSE' : 'CANCEL'", '`${verb} CASE',
  'self_approval', 'closure_separation',
  'deadlineState', 'due_soon', 'overdue',
  'encryptEvidenceJson', 'verifyEventChain', 'hashLinkedEvents: true',
  'REGULATORY_CASE_APPROVAL_REQUIRED'
]);
await requireMarkers('src/regulatory/regulatoryCaseHandler.js', 'Regulatory case API', [
  '/api/workforce-audit/regulatory-cases',
  'regulatory:case:approve', 'authFailure',
  'REGULATORY_CASE_BUSY', 'decodeSegment',
  'approve-response', 'submit-response'
]);
await requireMarkers('src/regulatory/regulatoryCaseServer.js', 'Regulatory runtime', [
  'createEvidenceAssuranceBundleAwareApp',
  'evidenceAssuranceBundleHandler',
  'createRegulatoryAuthenticationGateway',
  "'backup:restore'", "'governance:read'",
  'regulatoryCaseHandler', 'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Outer runtime', [
  'createRegulatoryCaseAwareApp'
]);
await requireMarkers('test/regulatoryCaseStore.test.js', 'Regulatory case safeguards', [
  'submitter, approver and closer separation',
  'revalidates immutable evidence',
  'contain no operational plaintext',
  'tampered encrypted indexes'
]);
await requireMarkers('test/regulatoryCaseHttp.test.js', 'Regulatory HTTP safeguards', [
  'separate permissions',
  'malformed paths fail cleanly',
  'closeAllConnections'
]);
await requireMarkers('test/regulatoryCaseServer.test.js', 'Regulatory runtime safeguards', [
  'maps governed permissions',
  "['governance:read', 'backup:restore']",
  'evidenceTimeAttestationGovernanceHandler'
]);
await requireMarkers('docs/regulatory-case-register.md', 'Regulatory case runbook', [
  'Do not paste regulator letters',
  'response submitter/approver separation',
  'response approver/final closer separation',
  'SUBMIT RESPONSE', 'APPROVE RESPONSE', 'CLOSE CASE',
  'not legal advice'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production regulatory case configuration', [
  'WORKFORCE_AUDIT_REGULATORY_CASE_MODE=shared-file',
  'WORKFORCE_AUDIT_REGULATORY_CASE_KEYS=',
  'WORKFORCE_AUDIT_REGULATORY_CASE_PRIMARY_KEY_ID=',
  'WORKFORCE_AUDIT_REGULATORY_CASE_DUE_SOON_HOURS=72'
]);

console.log('Regulatory case register build verification passed.');
