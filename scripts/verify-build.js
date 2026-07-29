import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
  'src/persistence/encryptedSnapshotStore.js',
  'src/persistence/backupManager.js',
  'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js',
  'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

const persistence = await readFile(new URL('../src/persistence/encryptedSnapshotStore.js', import.meta.url), 'utf8');
for (const marker of ['aes-256-gcm', 'writeEncrypted', 'inspectEncrypted', 'WORKFORCE_AUDIT_PRIMARY_KEY_ID']) {
  if (!persistence.includes(marker)) throw new Error(`Persistence build verification failed: missing ${marker}.`);
}

const backups = await readFile(new URL('../src/persistence/backupManager.js', import.meta.url), 'utf8');
for (const marker of ['checksumSha256', 'BACKUP_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_BACKUP_RETENTION', 'safety']) {
  if (!backups.includes(marker)) throw new Error(`Backup build verification failed: missing ${marker}.`);
}

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['/backups', 'backup:restore', 'RecoveryConflictError', 'x-request-id']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'Encrypted storage', 'Recovery points', 'x-api-key']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
