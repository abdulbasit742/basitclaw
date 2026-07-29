import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/externalScanContentReader.js',
  'src/evidence/externalScanJobOutbox.js',
  'src/evidence/externalScanJobLifecycle.js',
  'src/evidence/externalScanJobGovernanceHandler.js',
  'src/evidence/externalScanJobDeliveryHandler.js',
  'test/externalScanJobOutbox.test.js',
  'test/externalScanJobLifecycle.test.js',
  'test/externalScanJobServer.test.js',
  'docs/external-scan-delivery.md',
  'config/evidence-screening.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/externalScanContentReader.js', 'Scanner content reader', [
  'decryptEvidenceJson',
  'Scanner delivery evidence checksum verification failed',
  'contentAad'
]);
await requireMarkers('src/evidence/externalScanJobOutbox.js', 'Sealed scanner job outbox', [
  'rsa-oaep-sha256+aes-256-gcm',
  'timingSafeEqual',
  'requestReplayProtected',
  'encryptedRecords: true',
  'plaintextQueued: false',
  'completeFromAttestation',
  'request-replays',
  'reconcileLocationsLocked',
  'requeued: true'
]);
await requireMarkers('src/evidence/externalScanJobLifecycle.js', 'Scanner job lifecycle', [
  'EXTERNAL_SCAN_CLAIM_BUDGET_EXCEEDED',
  'attestation_timeout',
  'expiredPending',
  'expiredDelivered',
  'maxClaimBytes',
  'primaryPublicKeyId',
  'createManagedExternalScanJobOutboxFromEnvironment'
]);
await requireMarkers('src/evidence/externalScanEvidenceRegistry.js', 'Scanner job evidence composition', [
  'Only quarantined evidence versions can be queued',
  'queueExternalScanJob',
  'completeFromAttestation',
  'externalScanDelivery',
  'external-scan-release-policy',
  'requires enabled evidence screening',
  'requires signed external scanner attestations',
  'createManagedExternalScanJobOutboxFromEnvironment'
]);
await requireMarkers('src/evidence/externalScanJobGovernanceHandler.js', 'Scanner job governance API', [
  '/external-scan-jobs',
  'evidence:scan',
  'EXTERNAL_SCAN_JOB_BUSY'
]);
await requireMarkers('src/evidence/externalScanJobDeliveryHandler.js', 'Scanner pull API', [
  '/external-scanner/jobs/claim',
  '/acknowledge',
  '/fail',
  'HMAC realm'
]);
await requireMarkers('src/evidence/externalScanServer.js', 'Scanner delivery runtime', [
  'jobGovernanceHandler',
  'jobDeliveryHandler'
]);
await requireMarkers('docs/external-scan-delivery.md', 'Scanner delivery runbook', [
  'RSA-OAEP-SHA-256',
  'AES-256-GCM',
  'never auto-releases',
  'private key',
  'crash-interrupted',
  'dead-letter job',
  'claim byte budget',
  'primaryPublicKeyId'
]);
await requireMarkers('config/evidence-screening.production.env.example', 'Production scanner delivery configuration', [
  'WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_MODE=pull',
  'WORKFORCE_AUDIT_EXTERNAL_SCAN_DELIVERY_REQUIRED=true',
  'WORKFORCE_AUDIT_EXTERNAL_SCAN_MAX_CLAIM_BYTES=',
  'primaryPublicKeyId',
  'publicKeys'
]);
await requireMarkers('public/workforce-audit.html', 'Scanner delivery dashboard', [
  'Scan jobs pending',
  'Scan jobs inflight',
  'Scan delivery dead letters',
  'Plaintext queued'
]);

console.log('External scanner sealed-delivery build verification passed.');
