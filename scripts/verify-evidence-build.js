import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidenceRuntime.js', 'src/evidence/evidenceCrypto.js', 'src/evidence/evidenceHealthView.js',
  'src/evidence/evidenceRegistry.js', 'src/evidence/evidenceHandler.js', 'src/evidence/evidenceServer.js',
  'scripts/evidence-check.js', 'src/types/evidence.d.ts', 'docs/evidence-chain-of-custody.md',
  'test/evidenceRegistry.test.js', 'test/evidenceServer.test.js', 'public/workforce-audit.html'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function markers(path, expected) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of expected) {
    if (!content.includes(marker)) throw new Error(`Evidence build verification failed for ${path}: missing ${marker}.`);
  }
}

await markers('src/evidence/evidenceCrypto.js', ['aes-256-gcm', 'setAAD', 'fsyncSync', 'parseEvidenceKeyring']);
await markers('src/evidence/evidenceHealthView.js', ['publicEvidenceHealth', 'primaryKeyId', 'configuredKeyIds', 'mutex.directory']);
await markers('src/evidence/evidenceRegistry.js', [
  'EVIDENCE_INTEGRITY_FAILED', 'PLACEHOLDER_ID', 'PLH-ENG-', 'assertUsableReferences',
  'evidence.disposition_committed', 'purgePending', 'environmentValue', 'evidence_store_unavailable',
  'RELEASE HOLD', 'DISPOSE'
]);
await markers('src/evidence/evidenceHandler.js', [
  '/api/workforce-audit/evidence', 'x-evidence-sha256', 'backup:restore',
  'referencedByFindings', 'EVIDENCE_STORE_BUSY', 'evidenceTransportLimit', 'publicEvidenceHealth'
]);
await markers('src/evidence/evidenceServer.js', [
  'PassThrough', '/api/workforce-audit/findings', 'prepareEvidenceLifecycle',
  'createEvidenceReferenceMutex', 'EVIDENCE_REFERENCE_BUSY', 'Unhandled evidence server error',
  'publicEvidenceHealth'
]);
await markers('src/evidenceRuntime.js', ['cleanupRefresh', 'clearInterval', 'catch (error)']);
await markers('scripts/evidence-check.js', ['status', 'verify', 'events', 'EVIDENCE_COMMAND_FAILED']);
await markers('docs/evidence-chain-of-custody.md', [
  'chain of custody', 'legal hold', 'DISPOSE EVD-', 'purgePending', 'reference guard', 'WORM'
]);
await markers('public/workforce-audit.html', [
  'Evidence custody', 'Evidence items', 'Legal holds', 'Retention due', 'Evidence chain sequence'
]);

console.log('Evidence build verification passed.');
