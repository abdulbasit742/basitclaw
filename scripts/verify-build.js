import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
  'src/security/rateLimiter.js',
  'src/security/securityTelemetry.js',
  'scripts/generate-api-credential.js',
  'src/persistence/encryptedSnapshotStore.js',
  'src/persistence/backupManager.js',
  'src/resilience/replicaManager.js',
  'src/resilience/resilienceScheduler.js',
  'src/coordination/fileLeaseCoordinator.js',
  'src/coordination/fencedSnapshotStore.js',
  'src/coordination/coordinatedRegistry.js',
  'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js',
  'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts',
  'src/types/coordination.d.ts',
  'src/types/security.d.ts',
  'docs/api-security.md',
  '.github/workflows/ci.yml'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

const persistence = await readFile(new URL('../src/persistence/encryptedSnapshotStore.js', import.meta.url), 'utf8');
for (const marker of ['aes-256-gcm', 'writeEncrypted', 'inspectEncrypted', 'serialize', 'WORKFORCE_AUDIT_PRIMARY_KEY_ID']) {
  if (!persistence.includes(marker)) throw new Error(`Persistence build verification failed: missing ${marker}.`);
}

const backups = await readFile(new URL('../src/persistence/backupManager.js', import.meta.url), 'utf8');
for (const marker of ['checksumSha256', 'BACKUP_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_BACKUP_RETENTION', 'safety']) {
  if (!backups.includes(marker)) throw new Error(`Backup build verification failed: missing ${marker}.`);
}

const replicas = await readFile(new URL('../src/resilience/replicaManager.js', import.meta.url), 'utf8');
for (const marker of ['encrypted-file-replica', 'REPLICA_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_REPLICA_DIR', 'idempotent']) {
  if (!replicas.includes(marker)) throw new Error(`Replica build verification failed: missing ${marker}.`);
}

const coordinator = await readFile(new URL('../src/coordination/fileLeaseCoordinator.js', import.meta.url), 'utf8');
for (const marker of ['WRITE_COORDINATION_BUSY', 'fencingToken', 'stale', 'WORKFORCE_AUDIT_COORDINATION_MODE']) {
  if (!coordinator.includes(marker)) throw new Error(`Coordination build verification failed: missing ${marker}.`);
}

const fencedStore = await readFile(new URL('../src/coordination/fencedSnapshotStore.js', import.meta.url), 'utf8');
for (const marker of ['PERSISTENCE_FENCE_REJECTED', 'snapshot.fenced', 'latestFencingToken', 'bindFencingToken']) {
  if (!fencedStore.includes(marker)) throw new Error(`Fencing build verification failed: missing ${marker}.`);
}

const coordinatedRegistry = await readFile(new URL('../src/coordination/coordinatedRegistry.js', import.meta.url), 'utf8');
for (const marker of ['createRuntimeWorkforceAuditRegistry', 'createReadOnlyStore', 'getCoordinationStatus', 'createRegistry']) {
  if (!coordinatedRegistry.includes(marker)) throw new Error(`Coordinated registry build verification failed: missing ${marker}.`);
}

const scheduler = await readFile(new URL('../src/resilience/resilienceScheduler.js', import.meta.url), 'utf8');
for (const marker of ['WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES', 'runResilienceCycle', 'unref']) {
  if (!scheduler.includes(marker)) throw new Error(`Scheduler build verification failed: missing ${marker}.`);
}

const accessControl = await readFile(new URL('../src/security/accessControl.js', import.meta.url), 'utf8');
for (const marker of ['scryptSync', 'CREDENTIAL_REVOKED', 'credentialHealth', 'rotationRequired']) {
  if (!accessControl.includes(marker)) throw new Error(`Credential build verification failed: missing ${marker}.`);
}

const rateLimiter = await readFile(new URL('../src/security/rateLimiter.js', import.meta.url), 'utf8');
for (const marker of ['RATE_LIMITED', 'authFailure', 'sensitive', 'WORKFORCE_AUDIT_TRUST_PROXY_HOPS']) {
  if (!rateLimiter.includes(marker)) throw new Error(`Rate-limit build verification failed: missing ${marker}.`);
}

const telemetry = await readFile(new URL('../src/security/securityTelemetry.js', import.meta.url), 'utf8');
for (const marker of ['bounded-memory-hash-chain', 'ipFingerprint', 'WORKFORCE_AUDIT_SECURITY_EVENT_PEPPER', 'previousHash']) {
  if (!telemetry.includes(marker)) throw new Error(`Security telemetry build verification failed: missing ${marker}.`);
}

const generator = await readFile(new URL('../scripts/generate-api-credential.js', import.meta.url), 'utf8');
for (const marker of ['generateApiCredential', 'presentedKey', 'secretHash', 'randomBytes']) {
  if (!generator.includes(marker)) throw new Error(`Credential generator build verification failed: missing ${marker}.`);
}

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['/backups', 'backup:restore', 'coordination-status', 'security-status', 'security-events', 'RateLimitError', 'x-api-key-rotation-required']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'Write coordination', 'Credential health', 'API Security Events', 'x-api-key']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
