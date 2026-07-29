import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
  'src/persistence/encryptedSnapshotStore.js',
  'src/persistence/backupManager.js',
  'src/resilience/replicaManager.js',
  'src/resilience/resilienceScheduler.js',
  'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js',
  'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts',
  '.github/workflows/ci.yml'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

const replicas = await readFile(new URL('../src/resilience/replicaManager.js', import.meta.url), 'utf8');
for (const marker of ['encrypted-file-replica', 'REPLICA_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_REPLICA_DIR', 'idempotent']) {
  if (!replicas.includes(marker)) throw new Error(`Replica build verification failed: missing ${marker}.`);
}

const scheduler = await readFile(new URL('../src/resilience/resilienceScheduler.js', import.meta.url), 'utf8');
for (const marker of ['WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES', 'runResilienceCycle', 'unref']) {
  if (!scheduler.includes(marker)) throw new Error(`Scheduler build verification failed: missing ${marker}.`);
}

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['resilience-status', 'recovery-drills', '/replicate', 'resilience-cycle']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'Replica status', 'Recovery drill', 'x-api-key']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
