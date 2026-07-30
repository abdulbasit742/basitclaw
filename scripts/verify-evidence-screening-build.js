import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceScreeningEngine.js',
  'src/evidence/evidenceScreeningRegistry.js',
  'test/evidenceScreeningEngine.test.js',
  'test/evidenceScreeningRegistry.test.js',
  'docs/evidence-screening.md'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceScreeningEngine.js', 'Screening engine', [
  'MALWARE_EICAR_TEST_SIGNATURE',
  'DLP_PRIVATE_KEY_MATERIAL',
  'CONTENT_TYPE_EXTENSION_MISMATCH',
  'CONTAINER_REQUIRES_DEEP_SCAN',
  'wouldQuarantine',
  'WORKFORCE_AUDIT_EVIDENCE_SCREENING_MODE'
]);
await requireMarkers('src/evidence/evidenceScreeningRegistry.js', 'Screening registry', [
  'encryptEvidenceJson',
  'EVIDENCE_QUARANTINED',
  'RELEASE QUARANTINE',
  'REJECT EVIDENCE',
  'screening.quarantine_released',
  'assertVersionAccessible'
]);
await requireMarkers('src/evidence/evidenceHandler.js', 'Screening API', [
  '/screening',
  'screeningEvents',
  'releaseQuarantine',
  'rejectQuarantine',
  'evidence.quarantine_released'
]);
await requireMarkers('src/evidenceRuntime.js', 'Composed evidence runtime', [
  'createEvidencePreservationAwareApp'
]);
await requireMarkers('src/evidence/evidencePreservationServer.js', 'Preservation runtime composition', [
  'createExternalScanAwareApp'
]);
await requireMarkers('src/evidence/externalScanEvidenceRegistry.js', 'Composed screening registry', [
  'createScreenedEvidenceRegistryFromEnvironment'
]);
await requireMarkers('docs/evidence-screening.md', 'Screening runbook', [
  'quarantine',
  'RELEASE QUARANTINE',
  'REJECT EVIDENCE',
  'false-positive',
  'external antivirus'
]);
await requireMarkers('public/workforce-audit.html', 'Screening dashboard', [
  'Evidence quarantine',
  'Rejected evidence',
  'Screening reports'
]);

console.log('Evidence screening build verification passed.');
