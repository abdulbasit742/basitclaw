import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createEvidenceAssuranceBundleStore } from '../src/evidence/evidenceAssuranceBundleStore.js';
import {
  EvidenceAssuranceAcceptanceRequiredError,
  createEvidenceAssuranceAcceptanceStore,
  createEvidenceAssuranceAcceptanceStoreFromEnvironment
} from '../src/evidence/evidenceAssuranceAcceptanceStore.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { verifyAssuranceBundle } from '../scripts/verify-assurance-bundle.js';
import { verifyAssuranceAcceptanceReceipt } from '../scripts/verify-assurance-acceptance-receipt.js';

const tenantId = 'tenant-acceptance';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const content = Buffer.from('verified assurance evidence');
const recipientSecret = Buffer.alloc(48, 81);
const storageKey = Buffer.alloc(32, 82).toString('base64');
const acceptanceKey = Buffer.alloc(32, 83).toString('base64');
const fixedNow = new Date('2026-07-30T03:00:00.000Z');

function keyPairs() {
  return {
    recipient: generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    }),
    acceptance: generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    })
  };
}

function fixture() {
  const keys = keyPairs();
  const root = mkdtempSync(join(tmpdir(), 'assurance-acceptance-'));
  const recipients = {
    regulator: {
      keys: { h1: recipientSecret.toString('base64') },
      primaryPublicKeyId: 'r1',
      publicKeys: { r1: keys.recipient.publicKey }
    }
  };
  const base = createEvidenceAssuranceBundleStore({
    mode: 'pull', required: true,
    directory: join(root, 'bundles'),
    encryptionKeys: { b1: storageKey }, encryptionPrimaryKeyId: 'b1',
    recipients,
    bundleTtlMinutes: 60, claimLeaseMs: 300_000,
    maximumClaimBytes: 1_000_000, retention: 100,
    now: () => new Date(fixedNow)
  });
  const store = createEvidenceAssuranceAcceptanceStore({
    bundles: base, mode: 'enforce',
    directory: join(root, 'acceptance'),
    encryptionKeys: { a1: acceptanceKey }, encryptionPrimaryKeyId: 'a1',
    signingKeys: { s1: keys.acceptance.privateKey }, signingPrimaryKeyId: 's1',
    recipients, maxRecords: 100,
    now: () => new Date(fixedNow)
  });
  return { root, store, base, recipients, ...keys };
}

function bundleInput() {
  const version = {
    version: 1,
    filename: 'evidence.txt', mediaType: 'text/plain',
    sha256: sha256(content), sizeBytes: content.length,
    createdAt: '2026-07-30T02:59:00.000Z'
  };
  const sections = {
    item: { evidenceId, currentVersion: 1, status: 'active' },
    version,
    verification: { valid: true, headHash: 'b'.repeat(64) },
    custodyEvents: [], screening: { accessDecision: 'allow' },
    externalScans: [], preservationReceipts: [], timeAttestations: [],
    timeAttestationVerifications: [],
    assurancePosture: { cryptographicallyVerified: true, operationallyAcceptable: true, governedArchives: 0, operationalQuorumArchives: 0 },
    content: {
      filename: 'evidence.txt', mediaType: 'text/plain',
      sha256: sha256(content), sizeBytes: content.length,
      contentBase64: content.toString('base64')
    }
  };
  const sectionDigests = Object.fromEntries(Object.entries(sections).map(([name, value]) => [name, sha256(stableStringify(value))]));
  const manifest = {
    format: 'basitclaw-assurance-bundle-manifest', version: 1,
    tenantId, evidenceId, evidenceVersion: 1,
    contentSha256: sha256(content), recipientId: 'regulator',
    requestedBy: 'manager.one', purpose: 'Approved regulator assurance delivery',
    operationallyAcceptable: true, sectionDigests
  };
  manifest.bundleDigest = sha256(stableStringify(manifest));
  return {
    tenantId, evidenceId, evidenceVersion: 1, contentSha256: sha256(content),
    recipientId: 'regulator', requestedBy: 'manager.one',
    purpose: 'Approved regulator assurance delivery', manifest, evidence: sections
  };
}

function signed(body, operation, nonce) {
  const bytes = Buffer.from(JSON.stringify(body));
  const timestamp = fixedNow.toISOString();
  const canonical = ['regulator', 'h1', operation, timestamp, nonce, sha256(bytes)].join('\n');
  return {
    bytes,
    headers: {
      'x-basitclaw-recipient-id': 'regulator',
      'x-basitclaw-recipient-key-id': 'h1',
      'x-basitclaw-recipient-timestamp': timestamp,
      'x-basitclaw-recipient-nonce': nonce,
      'x-basitclaw-recipient-signature': createHmac('sha256', recipientSecret).update(canonical).digest('base64')
    }
  };
}

function filesUnder(directory) {
  const rows = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : rows.push(child);
    }
  };
  walk(directory);
  return rows;
}

test('recipient verifies, accepts, and receives an Ed25519-signed acceptance receipt', () => {
  const { store, recipient, acceptance } = fixture();
  const queued = store.queue(bundleInput());
  const claimRequest = signed({ limit: 1 }, 'claim', 'acceptance-claim-nonce-0001');
  const claimed = store.claimSigned(claimRequest.bytes, claimRequest.headers).bundles[0];
  assert.throws(() => store.acknowledgeSigned(claimed.bundleId), EvidenceAssuranceAcceptanceRequiredError);

  const verified = verifyAssuranceBundle({
    sealedPackage: claimed.sealedPackage,
    privateKeyPem: recipient.privateKey,
    claimToken: claimed.claimToken,
    now: () => new Date(fixedNow)
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.evidenceContentSha256, sha256(content));
  const acceptanceRequest = signed(
    verified.acceptanceRequest,
    `acceptance:${claimed.bundleId}`,
    'acceptance-submit-nonce-0001'
  );
  const accepted = store.acceptAndAcknowledgeSigned(claimed.bundleId, acceptanceRequest.bytes, acceptanceRequest.headers);
  assert.equal(accepted.bundle.state, 'delivered');
  assert.equal(accepted.bundle.acceptanceStatus, 'verified');
  assert.equal(accepted.acceptanceReceipt.verificationOutcome, 'verified');
  assert.equal(verifyAssuranceAcceptanceReceipt(accepted.acceptanceReceipt, acceptance.publicKey, tenantId).valid, true);
  assert.equal(store.verifyAcceptanceReceipt(tenantId, claimed.bundleId).valid, true);
  const listed = store.list(tenantId, { evidenceId });
  assert.equal(listed[0].acceptanceStatus, 'verified');
  assert.equal(listed[0].acceptanceReceipt.acceptanceId, accepted.acceptanceReceipt.acceptanceId);
  assert.equal(queued.bundle.packageSha256, claimed.packageSha256);
});

test('digest mismatch blocks delivery and leaves the claim available for a corrected acceptance', () => {
  const { store, recipient } = fixture();
  store.queue(bundleInput());
  const claimRequest = signed({ limit: 1 }, 'claim', 'acceptance-claim-nonce-0002');
  const claimed = store.claimSigned(claimRequest.bytes, claimRequest.headers).bundles[0];
  const verified = verifyAssuranceBundle({ sealedPackage: claimed.sealedPackage, privateKeyPem: recipient.privateKey, claimToken: claimed.claimToken, now: () => new Date(fixedNow) });
  const tampered = { ...verified.acceptanceRequest, bundleDigest: 'f'.repeat(64) };
  const request = signed(tampered, `acceptance:${claimed.bundleId}`, 'acceptance-submit-nonce-0002');
  assert.throws(() => store.acceptAndAcknowledgeSigned(claimed.bundleId, request.bytes, request.headers), /bundleDigest/);
  assert.equal(store.list(tenantId, { evidenceId })[0].state, 'claimed');
  assert.equal(store.list(tenantId, { evidenceId })[0].acceptanceStatus, 'pending');
});

test('acceptance records are encrypted and never persist claim tokens or evidence content', () => {
  const { root, store, recipient } = fixture();
  store.queue(bundleInput());
  const claimRequest = signed({ limit: 1 }, 'claim', 'acceptance-claim-nonce-0003');
  const claimed = store.claimSigned(claimRequest.bytes, claimRequest.headers).bundles[0];
  const verified = verifyAssuranceBundle({ sealedPackage: claimed.sealedPackage, privateKeyPem: recipient.privateKey, claimToken: claimed.claimToken, now: () => new Date(fixedNow) });
  const request = signed(verified.acceptanceRequest, `acceptance:${claimed.bundleId}`, 'acceptance-submit-nonce-0003');
  store.acceptAndAcknowledgeSigned(claimed.bundleId, request.bytes, request.headers);
  const raw = filesUnder(join(root, 'acceptance')).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(evidenceId), false);
  assert.equal(raw.includes(claimed.claimToken), false);
  assert.equal(raw.includes(content.toString('utf8')), false);
});

test('wrong recipient private keys and tampered acceptance receipts fail offline verification', () => {
  const { store, recipient, acceptance } = fixture();
  store.queue(bundleInput());
  const claimRequest = signed({ limit: 1 }, 'claim', 'acceptance-claim-nonce-0004');
  const claimed = store.claimSigned(claimRequest.bytes, claimRequest.headers).bundles[0];
  const wrong = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  assert.throws(() => verifyAssuranceBundle({ sealedPackage: claimed.sealedPackage, privateKeyPem: wrong.privateKey }));
  const verified = verifyAssuranceBundle({ sealedPackage: claimed.sealedPackage, privateKeyPem: recipient.privateKey, claimToken: claimed.claimToken, now: () => new Date(fixedNow) });
  const request = signed(verified.acceptanceRequest, `acceptance:${claimed.bundleId}`, 'acceptance-submit-nonce-0004');
  const accepted = store.acceptAndAcknowledgeSigned(claimed.bundleId, request.bytes, request.headers);
  const tampered = { ...accepted.acceptanceReceipt, verifierVersion: 'tampered-verifier' };
  assert.throws(() => verifyAssuranceAcceptanceReceipt(tampered, acceptance.publicKey, tenantId));
});

test('enabled acceptance configuration fails closed without dedicated keyrings', () => {
  const base = createEvidenceAssuranceBundleStore({ mode: 'disabled' });
  assert.throws(() => createEvidenceAssuranceAcceptanceStoreFromEnvironment({
    bundles: base,
    env: { WORKFORCE_AUDIT_ASSURANCE_ACCEPTANCE_MODE: 'enforce' }
  }), (error) => error.details.reason === 'missing_acceptance_configuration');
});

function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
