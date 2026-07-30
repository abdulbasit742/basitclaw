import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/services/auditSampling.js',
  'src/services/workforceAuditService.js',
  'src/auditTestProgrammeHandler.js',
  'src/auditTestProgrammeServer.js',
  'src/types/audit-test-programmes.d.ts',
  'test/auditSampling.test.js',
  'test/auditTestProgramme.test.js',
  'test/auditTestProgrammeHttp.test.js',
  'docs/audit-test-programmes.md'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/services/auditSampling.js', 'Audit sampling engine', [
  'basitclaw-audit-sampling-v1',
  "new Set(['random', 'systematic', 'stratified'])",
  'populationDigest',
  'manifest.sort((left, right) => left.recordId.localeCompare(right.recordId))',
  'systematicSelection',
  'stratifiedSelection',
  'wilsonUpperDeviationBound',
  'effective_with_exceptions'
]);
await requireMarkers('src/services/workforceAuditService.js', 'Audit test programme lifecycle', [
  'testProgrammes',
  'test_programme.created',
  'test_sample.executed',
  'test_sample.retested',
  'test_programme.submitted',
  'test_programme.finalised',
  'reviewer must be independent',
  'Placeholder evidence cannot support',
  'FINALISE ${programme.id}',
  'verifyTestProgramme',
  'testProgrammes = previousState.testProgrammes'
]);
await requireMarkers('src/auditTestProgrammeHandler.js', 'Audit test programme API', [
  '/api/workforce-audit/test-programmes',
  '/test-programmes$',
  '/samples\/([^/]+)\/results',
  '/submit$',
  '/review$',
  "return 'engagement:write'",
  'decodeSegment',
  'audit-test-programmes'
]);
await requireMarkers('src/auditTestProgrammeServer.js', 'Audit test programme server', [
  'createEvidenceTimeAttestationAwareApp',
  'auditTestProgrammeHandler',
  'resilienceScheduler',
  'auditRegistry'
]);
await requireMarkers('src/evidenceRuntime.js', 'Audit test programme runtime', [
  'createAuditTestProgrammeAwareApp'
]);
await requireMarkers('test/auditSampling.test.js', 'Audit sampling safeguards', [
  'independent of population input order',
  'represents every stratum',
  'detects altered selected-record order',
  'fail conservatively on small samples'
]);
await requireMarkers('test/auditTestProgramme.test.js', 'Audit lifecycle safeguards', [
  'preparer and reviewer must be different identities',
  'retests append attempts',
  'Placeholder evidence blocks submission',
  'differs from statistics'
]);
await requireMarkers('test/auditTestProgrammeHttp.test.js', 'Audit programme HTTP safeguards', [
  'enforces manager review',
  'requires manager permission',
  'malformed encoded programme IDs',
  'server.close(resolve)'
]);
await requireMarkers('docs/audit-test-programmes.md', 'Audit test programme runbook', [
  'population completeness',
  'one-sided Wilson',
  'does not replace professional judgement',
  'FINALISE TPG-',
  'finalised programme is immutable'
]);

console.log('Governed audit test-programme build verification passed.');
