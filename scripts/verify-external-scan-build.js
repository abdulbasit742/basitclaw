import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/externalScanAttestationRegistry.js',
  'src/evidence/externalScanEvidenceRegistry.js',
  'src/evidence/externalScanCallbackHandler.js',
  'src/evidence/externalScanManagementHandler.js',
  'src/evidence/externalScanServer.js',
  'test/externalScanAttestationRegistry.test.js',
  'test/externalScanHttp.test.js',
  'docs/external-scanner-attestations.md',
  'config/evidence-screening.production.env.example'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/externalScanAttestationRegistry.js', 'External scan attestation registry', [
  'timingSafeEqual',
  'EXTERNAL_SCAN_AUTHENTICATION_FAILED',
  'EVIDENCE_EXTERNAL_SCAN_REQUIRED',
  'encryptEvidenceJson',
  'contentSha256',
  'requiredForRelease',
  'recordHash'
]);
await requireMarkers('src/evidence/externalScanEvidenceRegistry.js', 'External scan release gate', [
  'external_verdict_not_clean',
  'requireCleanForRelease',
  'recordExternalScanAttestation',
  'externalScanAttestations',
  'externalScanStatus'
]);
await requireMarkers('src/evidence/externalScanCallbackHandler.js', 'External scan callback', [
  '/api/workforce-audit/external-scanner/attestations',
  'x-content-type-options',
  'HMAC realm',
  'external_scan.authentication_failed'
]);
await requireMarkers('src/evidence/externalScanManagementHandler.js', 'External scan management API', [
  '/api/workforce-audit/external-scanner/status',
  '/external-scans',
  'governance:read'
]);
await requireMarkers('src/evidenceRuntime.js', 'External scan runtime', [
  'createExternalScanAwareApp'
]);
await requireMarkers('docs/external-scanner-attestations.md', 'External scan runbook', [
  'HMAC-SHA256',
  'never auto-release',
  'contentSha256',
  'RELEASE QUARANTINE',
  'sidecar'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production external scanner configuration', [
  'WORKFORCE_AUDIT_EXTERNAL_SCANNER_MODE=enforce',
  'WORKFORCE_AUDIT_EXTERNAL_SCANNER_REQUIRED_FOR_RELEASE=true',
  'WORKFORCE_AUDIT_EXTERNAL_SCANNER_PROVIDERS='
]);

console.log('External scanner attestation build verification passed.');
