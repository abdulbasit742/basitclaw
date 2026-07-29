import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/security/accessControl.js',
  'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js',
  'src/services/governanceLedger.js',
  'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts'
];

for (const file of requiredFiles) {
  await access(new URL(`../${file}`, import.meta.url));
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
for (const marker of ['Workforce Audit Assurance', 'x-api-key', 'sessionStorage']) {
  if (!page.includes(marker)) throw new Error(`Dashboard build verification failed: missing ${marker}.`);
}

const server = await readFile(new URL('../src/server.js', import.meta.url), 'utf8');
for (const marker of ['governance-integrity', 'createAccessController', 'x-request-id']) {
  if (!server.includes(marker)) throw new Error(`Server build verification failed: missing ${marker}.`);
}

console.log('Build verification passed.');
