#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyAndDecryptDisclosurePackage } from '../src/evidence/evidenceDisclosureVerifier.js';

export function runDisclosureVerification({ bundlePath, recipientPrivateKeyPath, enterprisePublicKeysPath, showPayload = false, allowExpired = false } = {}) {
  if (!bundlePath || !recipientPrivateKeyPath || !enterprisePublicKeysPath) {
    throw new TypeError('bundlePath, recipientPrivateKeyPath and enterprisePublicKeysPath are required.');
  }
  const packageValue = JSON.parse(readFileSync(resolve(bundlePath), 'utf8'));
  const recipientPrivateKey = readFileSync(resolve(recipientPrivateKeyPath), 'utf8');
  const keyConfig = JSON.parse(readFileSync(resolve(enterprisePublicKeysPath), 'utf8'));
  const enterprisePublicKeys = Object.fromEntries(Object.entries(keyConfig).map(([keyId, value]) => {
    const path = typeof value === 'string' ? value : value?.path;
    if (!path) throw new TypeError(`Enterprise public key ${keyId} must reference a PEM file path.`);
    return [keyId, readFileSync(resolve(path), 'utf8')];
  }));
  const result = verifyAndDecryptDisclosurePackage(packageValue, { recipientPrivateKey, enterprisePublicKeys, allowExpired });
  return showPayload ? result : {
    valid: result.valid,
    bundleId: result.bundleId,
    signingKeyId: result.signingKeyId,
    recipientKeyId: result.recipientKeyId,
    createdAt: result.createdAt,
    expiresAt: result.expiresAt,
    manifestSha256: result.manifestSha256,
    evidenceReference: result.evidenceReference,
    versionCount: result.versionCount,
    rawEvidenceIncluded: false
  };
}

function parseArguments(argv) {
  const positional = [];
  let showPayload = false;
  let allowExpired = false;
  for (const argument of argv) {
    if (argument === '--show-payload') showPayload = true;
    else if (argument === '--allow-expired') allowExpired = true;
    else positional.push(argument);
  }
  if (positional.length !== 3) {
    throw new TypeError('Usage: npm run disclosure:verify -- <bundle.json> <recipient-private-key.pem> <enterprise-public-keys.json> [--show-payload] [--allow-expired]');
  }
  return { bundlePath: positional[0], recipientPrivateKeyPath: positional[1], enterprisePublicKeysPath: positional[2], showPayload, allowExpired };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const result = runDisclosureVerification(parseArguments(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ valid: false, code: error?.code ?? 'DISCLOSURE_VERIFICATION_FAILED', error: error?.message, details: error?.details }, null, 2)}\n`);
    process.exitCode = 1;
  }
}
