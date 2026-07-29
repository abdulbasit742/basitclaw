import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js', 'src/security/accessControl.js', 'src/security/rateLimiter.js',
  'src/security/sharedRateLimiter.js', 'src/security/fileMutex.js', 'src/security/securityTelemetry.js',
  'src/security/securityArchiveCodec.js', 'src/security/securityArchiveFilesystem.js',
  'src/security/securityEventArchive.js', 'src/security/securityAlertCodec.js',
  'src/security/securityAlertOutbox.js', 'src/security/securityAlertDispatcher.js',
  'src/security/securityAlertRuntime.js', 'scripts/generate-api-credential.js',
  'scripts/security-alerts.js', 'src/persistence/encryptedSnapshotStore.js',
  'src/persistence/backupManager.js', 'src/resilience/replicaManager.js',
  'src/resilience/resilienceScheduler.js', 'src/coordination/fileLeaseCoordinator.js',
  'src/coordination/fencedSnapshotStore.js', 'src/coordination/coordinatedRegistry.js',
  'src/services/workforceAuditService.js', 'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js', 'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts', 'src/types/coordination.d.ts', 'src/types/security.d.ts',
  'docs/api-security.md', '.github/workflows/ci.yml'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/persistence/encryptedSnapshotStore.js', 'Persistence', ['aes-256-gcm', 'writeEncrypted', 'inspectEncrypted', 'serialize', 'WORKFORCE_AUDIT_PRIMARY_KEY_ID']);
await requireMarkers('src/persistence/backupManager.js', 'Backup', ['checksumSha256', 'BACKUP_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_BACKUP_RETENTION', 'safety']);
await requireMarkers('src/resilience/replicaManager.js', 'Replica', ['encrypted-file-replica', 'REPLICA_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_REPLICA_DIR', 'idempotent']);
await requireMarkers('src/coordination/fileLeaseCoordinator.js', 'Coordination', ['WRITE_COORDINATION_BUSY', 'fencingToken', 'stale', 'WORKFORCE_AUDIT_COORDINATION_MODE']);
await requireMarkers('src/coordination/fencedSnapshotStore.js', 'Fencing', ['PERSISTENCE_FENCE_REJECTED', 'snapshot.fenced', 'latestFencingToken', 'bindFencingToken']);
await requireMarkers('src/coordination/coordinatedRegistry.js', 'Coordinated registry', ['createRuntimeWorkforceAuditRegistry', 'createReadOnlyStore', 'getCoordinationStatus', 'createRegistry']);
await requireMarkers('src/resilience/resilienceScheduler.js', 'Scheduler', ['WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES', 'runResilienceCycle', 'unref']);
await requireMarkers('src/security/accessControl.js', 'Credential', ['scryptSync', 'CREDENTIAL_REVOKED', 'credentialHealth', 'rotationRequired']);
await requireMarkers('src/security/rateLimiter.js', 'Rate limit', ['RATE_LIMITED', 'shared-file', 'WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED', 'WORKFORCE_AUDIT_TRUST_PROXY_HOPS']);
await requireMarkers('src/security/sharedRateLimiter.js', 'Shared rate limit', ['shared-file-fixed-window', 'RATE_LIMIT_STORE_UNAVAILABLE', 'identityHash', 'atomicWriteJson']);
await requireMarkers('src/security/fileMutex.js', 'Security mutex', ['SECURITY_CONTROL_BUSY', 'stale', 'owner.json', 'withLock']);
await requireMarkers('src/security/securityEventArchive.js', 'Security archive', ['SECURITY_ARCHIVE_INTEGRITY_FAILED', 'shared-file-encrypted-hash-chain', 'prunePlanPath', 'recoverHeadLocked']);
await requireMarkers('src/security/securityArchiveCodec.js', 'Security archive codec', ['aes-256-gcm', 'signAnchor', 'signPrunePlan', 'ciphertext']);
await requireMarkers('src/security/securityArchiveFilesystem.js', 'Security archive filesystem', ['prune-plan.json', 'appendSegment', 'atomicWrite', 'fsyncDirectory']);
await requireMarkers('src/security/securityAlertCodec.js', 'Security alert codec', ['x-basitclaw-signature', 'Retry-After', 'validateWebhookEndpoint', 'minimumSeverity']);
await requireMarkers('src/security/securityAlertOutbox.js', 'Security alert outbox', ['shared-file-durable-outbox', 'dead-letter', 'claimExpiresAt', 'Recovered after an expired in-flight claim']);
await requireMarkers('src/security/securityAlertDispatcher.js', 'Security alert dispatcher', ['signed-webhook-durable-outbox', 'SECURITY_ALERT_DELIVERY_UNAVAILABLE', 'dispatchDue', 'maximum_attempts_exceeded']);
await requireMarkers('src/security/securityAlertRuntime.js', 'Security alert runtime', ['WORKFORCE_AUDIT_SECURITY_ALERT_AUTO_START', 'WORKFORCE_AUDIT_SECURITY_ALERT_DEAD_LETTER_RETENTION', 'createSecurityAlertOutbox']);
await requireMarkers('src/security/securityTelemetry.js', 'Security telemetry', ['bounded-memory-plus-encrypted-archive', 'listArchived', 'verifyArchive', 'alertDelivery']);
await requireMarkers('scripts/generate-api-credential.js', 'Credential generator', ['generateApiCredential', 'presentedKey', 'secretHash', 'randomBytes']);
await requireMarkers('scripts/security-alerts.js', 'Security alert CLI', ['dead-letters', 'dispatchDue', 'requeue', 'WORKFORCE_AUDIT_SECURITY_ALERT_AUTO_START']);
await requireMarkers('src/server.js', 'Server', ['/backups', 'backup:restore', 'security-archive-events', 'security-archive-integrity', 'RateLimitStoreError', 'publicSecurityHealth']);
await requireMarkers('public/workforce-audit.html', 'Dashboard', ['Workforce Audit Assurance', 'Distributed rate limit', 'Security archive', 'Security alert delivery', 'API Security Events', 'x-api-key']);

console.log('Build verification passed.');
