#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyEvidenceAssuranceBundle } from '../src/evidence/evidenceAssuranceBundleVerifier.js';

const MAX_INPUT_BYTES = 150_000_000;
const MAX_KEY_BYTES = 65_536;

try {
  const options = parseArguments(process.argv.slice(2));
  const packageInput = readJson(options.packagePath, MAX_INPUT_BYTES, 'assurance bundle package');
  const sealedPackage = packageInput.sealedPackage ?? packageInput;
  const privateKeyPem = readText(options.privateKeyPath, MAX_KEY_BYTES, 'recipient private key');
  const report = verifyEvidenceAssuranceBundle({
    sealedPackage,
    privateKeyPem,
    expectedBundleId: options.expectedBundleId ?? packageInput.bundleId ?? null,
    expectedPackageSha256: options.expectedPackageSha256 ?? packageInput.packageSha256 ?? null,
    expectedRecipientPublicKeyId: options.expectedRecipientPublicKeyId,
    requireOperationallyAcceptable: !options.allowOperationallyUnacceptable
  });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (options.outputPath) writeFileSync(resolve(options.outputPath), output, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  else process.stdout.write(output);
} catch (error) {
  process.stderr.write(`${JSON.stringify({ success: false, error: error.message, code: error.code ?? 'ASSURANCE_BUNDLE_VERIFIER_FAILED', details: error.details ?? {} })}\n`);
  process.exitCode = 1;
}

function parseArguments(args) {
  const options = { packagePath: null, privateKeyPath: null, expectedBundleId: null, expectedPackageSha256: null, expectedRecipientPublicKeyId: null, allowOperationallyUnacceptable: false, outputPath: null };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--allow-operationally-unacceptable') { options.allowOperationallyUnacceptable = true; continue; }
    const value = args[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`A value is required for ${argument}.`);
    index += 1;
    if (argument === '--package') options.packagePath = value;
    else if (argument === '--private-key') options.privateKeyPath = value;
    else if (argument === '--expected-bundle-id') options.expectedBundleId = value;
    else if (argument === '--expected-package-sha256') options.expectedPackageSha256 = value;
    else if (argument === '--expected-recipient-key-id') options.expectedRecipientPublicKeyId = value;
    else if (argument === '--output') options.outputPath = value;
    else throw new Error(`Unsupported argument ${argument}.`);
  }
  if (!options.packagePath) throw new Error('--package is required.');
  if (!options.privateKeyPath) throw new Error('--private-key is required.');
  return options;
}

function readText(path, maximumBytes, label) {
  const bytes = readFileSync(resolve(path));
  if (bytes.length > maximumBytes) throw new Error(`The ${label} exceeds ${maximumBytes} bytes.`);
  return bytes.toString('utf8');
}
function readJson(path, maximumBytes, label) {
  const text = readText(path, maximumBytes, label);
  try { return JSON.parse(text); }
  catch { throw new Error(`The ${label} must contain valid JSON.`); }
}
