import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { verifyPortableEvidenceBundle } from '../src/evidence/evidenceVerificationBundle.js';

export function verifyBundleFile(bundlePath, publicKeysPath, options = {}) {
  const document = JSON.parse(readFileSync(bundlePath, 'utf8'));
  const bundle = document?.bundle ?? document?.data?.bundle ?? document?.data?.data?.bundle ?? document;
  const publicKeys = JSON.parse(readFileSync(publicKeysPath, 'utf8'));
  return verifyPortableEvidenceBundle(bundle, publicKeys, options);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , bundlePath, publicKeysPath] = process.argv;
  if (!bundlePath || !publicKeysPath) {
    console.error('Usage: node scripts/verify-evidence-bundle.js <bundle.json> <trusted-public-keys.json>');
    process.exitCode = 2;
  } else {
    try {
      const result = verifyBundleFile(bundlePath, publicKeysPath);
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } catch (error) {
      console.error('Evidence verification bundle failed validation.', {
        code: error?.code,
        error: error?.message,
        details: error?.details
      });
      process.exitCode = 1;
    }
  }
}
