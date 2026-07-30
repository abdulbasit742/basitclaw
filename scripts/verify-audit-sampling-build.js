import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/sampling/auditSamplingEngine.js',
  'src/sampling/auditSamplingStore.js',
  'src/sampling/auditSamplingRegistry.js',
  'src/sampling/auditSamplingHandler.js',
  'src/sampling/auditSamplingServer.js',
  'src/types/audit-sampling.d.ts',
  'test/auditSamplingEngine.test.js',
  'test/auditSamplingStore.test.js',
  'test/auditSamplingHttp.test.js',
  'docs/audit-sampling.md',
  'config/audit-sampling.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
}

await requireMarkers('src/sampling/auditSamplingEngine.js', 'Sampling engine', [
  'simple_random', 'systematic', 'monetary_unit', 'stratified_random',
  'sampleWithoutReplacement', 'rejection', 'amountMinorUnits', 'populationRoot', 'selectionHash'
]);
await requireMarkers('src/sampling/auditSamplingStore.js', 'Sampling store', [
  'basitclaw-audit-sampling-plan-v1', 'encryptEvidenceJson', 'seedCommitment',
  'preparer cannot approve', 'APPROVE SAMPLE', 'CANCEL SAMPLE',
  'plan.approved', 'event chain', 'sourceReferencesPublic: false',
  'WORKFORCE_AUDIT_SAMPLING_KEYS'
]);
await requireMarkers('src/sampling/auditSamplingRegistry.js', 'Sampling evidence composition', [
  'evidenceContentSha256', 'assertVersionAccessible', 'revalidateEvidenceBinding',
  'staleEvidenceBindings', 'statisticalValidityAsserted: false',
  'createEvidenceAssuranceBundleRegistryFromEnvironment'
]);
await requireMarkers('src/sampling/auditSamplingHandler.js', 'Sampling API', [
  '/api/workforce-audit/sampling-plans/status', 'fieldwork:write', 'engagement:write',
  'decodeSegment', 'authFailure', 'sourceReferencesPublic: false'
]);
await requireMarkers('src/sampling/auditSamplingServer.js', 'Sampling runtime composition', [
  'createEvidenceAssuranceBundleAwareApp', 'auditSamplingHandler', 'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Sampling outer runtime', ['createAuditSamplingAwareApp']);
await requireMarkers('test/auditSamplingEngine.test.js', 'Sampling engine regressions', [
  'without replacement', 'systematic', 'monetary-unit', 'stratified', 'order-independent'
]);
await requireMarkers('test/auditSamplingStore.test.js', 'Sampling workflow regressions', [
  'preparer cannot approve', 'ciphertext tampering', 'evidence binding', 'seed only after independent approval'
]);
await requireMarkers('docs/audit-sampling.md', 'Sampling runbook', [
  'does not prove', 'Rejection sampling avoids modulo bias', 'Maker–checker',
  'reproducible', 'statistical', 'sourceReference'
]);
await requireMarkers('config/audit-sampling.production.env.example', 'Sampling production configuration', [
  'WORKFORCE_AUDIT_SAMPLING_MODE=shared-file',
  'WORKFORCE_AUDIT_SAMPLING_KEYS=',
  'WORKFORCE_AUDIT_SAMPLING_PRIMARY_KEY_ID=',
  'WORKFORCE_AUDIT_SAMPLING_MAX_POPULATION_ITEMS='
]);

console.log('Governed audit sampling build verification passed.');
