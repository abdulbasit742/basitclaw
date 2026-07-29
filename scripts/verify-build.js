import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js',
  'src/services/workforceAuditService.js',
  'public/workforce-audit.html',
  'src/types/workforceAudit.d.ts'
];

for (const file of requiredFiles) {
  await access(new URL(`../${file}`, import.meta.url));
}

const page = await readFile(new URL('../public/workforce-audit.html', import.meta.url), 'utf8');
if (!page.includes('Workforce Audit Assurance')) {
  throw new Error('Dashboard build verification failed: expected heading missing.');
}

console.log('Build verification passed.');
