import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
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

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['/backups', 'backup:restore', 'resilience-status', 'coordination-status', 'CoordinationBusyError']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'Recovery points', 'Replica status', 'Write coordination', 'x-api-key']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
