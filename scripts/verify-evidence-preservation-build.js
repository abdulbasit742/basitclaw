import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidencePreservationStore.js',
  'src/evidence/evidencePreservationRegistry.js',
  'src/evidence/evidencePreservationHandler.js',
  'src/evidence/evidencePreservationServer.js',
  'test/evidencePreservationStore.test.js',
  'docs/evidence-preservation.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidencePreservationStore.js', 'Evidence preservation store', [
  'basitclaw-evidence-preservation-object',
  'basitclaw-evidence-preservation-receipt',
  'writeJsonExclusive',
  'timingSafeEqual',
  'signedReceipts: true',
  'createOnly: true',
  'deletionApi: false',
  'backend-confirmed-write-once',
  'verifiedForVersion',
  'EVIDENCE_PRESERVATION_REQUIRED'
]);
await requireMarkers('src/evidence/evidencePreservationRegistry.js', 'Evidence preservation composition', [
  'confirmation must be exactly PRESERVE',
  'missingVersions',
  'requiredForDisposition',
  'evidencePreservationStatus',
  'preservation.verifyTenant',
  'createEvidencePreservationRegistryFromEnvironment'
]);
await requireMarkers('src/evidence/evidencePreservationHandler.js', 'Evidence preservation API', [
  '/api/workforce-audit/evidence-preservation/status',
  '/preservations',
  'evidence:preserve',
  'decodeSegment',
  'EVIDENCE_PRESERVATION_BUSY'
]);
await requireMarkers('src/evidence/evidencePreservationServer.js', 'Evidence preservation server', [
  'createExternalScanAwareApp',
  'evidencePreservationHandler',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Evidence preservation runtime', [
  'createEvidencePreservationAwareApp'
]);
await requireMarkers('src/security/accessControl.js', 'Evidence preservation access control', [
  'evidence:preserve'
]);
await requireMarkers('docs/evidence-preservation.md', 'Evidence preservation runbook', [
  'write-once',
  'retention extension',
  'PRESERVE EVD-',
  'does not make an ordinary filesystem WORM',
  'no deletion endpoint'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production preservation configuration', [
  'WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_MODE=shared-file',
  'WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_REQUIRED_FOR_DISPOSITION=true',
  'WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_IMMUTABLE_BACKEND_CONFIRMED=true',
  'WORKFORCE_AUDIT_EVIDENCE_PRESERVATION_SIGNING_SECRETS='
]);

console.log('Evidence preservation build verification passed.');
