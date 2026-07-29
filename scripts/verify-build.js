import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
  'src/persistence/encryptedSnapshotStore.js',
  'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js',
  'public/workforce-audit.html'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

const persistence = await readFile(new URL('../src/persistence/encryptedSnapshotStore.js', import.meta.url), 'utf8');
for (const marker of ['aes-256-gcm', 'renameSync', 'WORKFORCE_AUDIT_PRIMARY_KEY_ID', 'PersistenceError']) {
  if (!persistence.includes(marker)) throw new Error(`Persistence build verification failed: missing ${marker}.`);
}

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['persistence-health', 'PERSISTENCE_UNAVAILABLE', 'x-request-id']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'Encrypted storage', 'x-api-key']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
