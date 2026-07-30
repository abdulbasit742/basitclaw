import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/evidence/evidenceVerificationBundle.js',
  'src/evidence/evidenceVerificationBundleHandler.js',
  'src/evidence/evidenceVerificationBundleServer.js',
  'test/evidenceVerificationBundle.test.js',
  'test/evidenceVerificationBundleHttp.test.js',
  'scripts/verify-evidence-bundle.js',
  'docs/evidence-verification-bundles.md',
  'src/types/evidence-verification-bundles.d.ts',
  'config/evidence-verification-bundles.production.env.example'
];
for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/evidence/evidenceVerificationBundle.js', 'Portable bundle service', [
  'basitclaw-portable-evidence-verification-bundle',
  'verifyPortableEvidenceBundle',
  'ed25519',
  'rsa-pss-sha256',
  'rawEvidenceContentIncluded: false',
  'FORBIDDEN_PROOF_KEYS',
  'purposeDigest',
  'missing_bundle_signing_configuration',
  'Independent time-attestation quorum is required before proof export'
]);
await requireMarkers('src/evidence/evidenceVerificationBundleHandler.js', 'Portable bundle API', [
  '/api/workforce-audit/evidence-verification-bundles/status',
  '/api/workforce-audit/evidence-verification-bundles/verify',
  'evidence:preserve',
  'content-disposition',
  'decodeSegment',
  'evidence.verification_bundle_exported'
]);
await requireMarkers('src/evidence/evidenceVerificationBundleServer.js', 'Portable bundle server', [
  'createEvidenceTimeAttestationAwareApp',
  'evidenceVerificationBundleHandler',
  'resilienceScheduler'
]);
await requireMarkers('src/evidenceRuntime.js', 'Portable bundle runtime', [
  'createEvidenceVerificationBundleAwareApp'
]);
await requireMarkers('docs/evidence-verification-bundles.md', 'Portable bundle runbook', [
  'never contains raw evidence bytes',
  'EXPORT PROOF EVD-',
  'evidence:bundle:verify',
  'cannot revoke copies already delivered'
]);
await requireMarkers('config/evidence-verification-bundles.production.env.example', 'Portable bundle production overlay', [
  'WORKFORCE_AUDIT_EVIDENCE_BUNDLE_MODE=signed',
  'WORKFORCE_AUDIT_EVIDENCE_BUNDLE_REQUIRE_TIME_QUORUM=true',
  'WORKFORCE_AUDIT_EVIDENCE_BUNDLE_SIGNING_KEYS=',
  'WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PROTECTED_PERMISSIONS='
]);

console.log('Portable evidence verification-bundle build verification passed.');
