import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  constants
} from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import {
  EvidenceAssuranceBundleAuthenticationError,
  createEvidenceAssuranceBundleStore,
  createEvidenceAssuranceBundleStoreFromEnvironment
} from '../src/evidence/evidenceAssuranceBundleStore.js';

const encryptionKey = Buffer.alloc(32, 91).toString('base64');
const recipientSecret = Buffer.alloc(48, 92);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const recipientId = 'external-auditor';
const tenantId = 'tenant-assurance';
const evidenceId = `EVD-${'b'.repeat(32)}`;

function fixture(options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'assurance-bundles-'));
  let clock = new Date('2026-07-30T01:00:00.000Z');
  const store = createEvidenceAssuranceBundleStore({
    mode: 'pull',
    required: true,
    directory,
    encryptionKeys: { bundle: encryptionKey },
    encryptionPrimaryKeyId: 'bundle',
    recipients: {
      [recipientId]: {
        keys: { h1: recipientSecret.toString('base64') },
        primaryPublicKeyId: 'r1',
        publicKeys: { r1: rsa.publicKey }
      }
    },
    bundleTtlMinutes: options.bundleTtlMinutes ?? 60,
    claimLeaseMs: 30_000,
    maximumClaimBytes: 2_000_000,
    retention: 100,
    now: () => new Date(clock)
  });
  return { store, directory, get clock() { return clock; }, set clock(value) { clock = value; } };
}

function queueInput(overrides = {}) {
  const content = Buffer.from('confidential payroll evidence for an external auditor');
  const evidence = {
    content: {
      filename: 'payroll.csv',
      mediaType: 'text/csv',
      sha256: sha256(content),
      sizeBytes: content.length,
      contentBase64: content.toString('base64')
    },
    custodyEvents: [{ sequence: 1, action: 'evidence.ingested' }],
    preservationReceipts: [{ archiveId: `ARC-${'c'.repeat(32)}` }],
    timeAttestations: [{ attestationId: `TSA-${'d'.repeat(32)}` }]
  };
  const manifest = {
    format: 'basitclaw-assurance-bundle-manifest',
    version: 1,
    bundleDigest: sha256('manifest'),
    sectionDigests: { evidence: sha256(JSON.stringify(evidence)) }
  };
  return {
    tenantId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256: evidence.content.sha256,
    recipientId,
    requestedBy: 'manager.one',
    purpose: 'Independent external audit assurance review',
    manifest,
    evidence,
    ...overrides
  };
}

function signed(body, operation, timestamp, nonce) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = [recipientId, 'h1', operation, timestamp, nonce, sha256(bytes)].join('\n');
  return {
    bytes,
    headers: {
      'x-basitclaw-recipient-id': recipientId,
      'x-basitclaw-recipient-key-id': 'h1',
      'x-basitclaw-recipient-timestamp': timestamp,
      'x-basitclaw-recipient-nonce': nonce,
      'x-basitclaw-recipient-signature': createHmac('sha256', recipientSecret).update(canonical).digest('base64')
    }
  };
}

function decryptPackage(sealed) {
  const key = privateDecrypt({ key: rsa.privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(sealed.wrappedKey, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'));
  decipher.setAAD(Buffer.from(sealed.aad, 'base64'));
  decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext, 'base64')), decipher.final()]);
  return { plaintext, payload: JSON.parse(plaintext.toString('utf8')) };
}

function allFiles(directory) {
  const rows = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) walk(child); else rows.push(child);
    }
  };
  walk(directory);
  return rows;
}

test('recipient can decrypt a claimed assurance bundle only with its RSA private key', () => {
  const fx = fixture();
  const queued = fx.store.queue(queueInput());
  assert.equal(queued.duplicate, false);
  const timestamp = fx.clock.toISOString();
  const claim = signed({ limit: 1 }, 'claim', timestamp, 'claim-nonce-0000000001');
  const result = fx.store.claimSigned(claim.bytes, claim.headers);
  assert.equal(result.bundles.length, 1);
  const { plaintext, payload } = decryptPackage(result.bundles[0].sealedPackage);
  assert.equal(payload.bundleId, queued.bundle.bundleId);
  assert.equal(payload.evidence.content.contentBase64, Buffer.from('confidential payroll evidence for an external auditor').toString('base64'));
  assert.equal(sha256(plaintext), result.bundles[0].sealedPackage.plaintextSha256);
  assert.equal(payload.manifest.bundleDigest, sha256('manifest'));
});

test('queue files contain neither evidence plaintext nor tenant and evidence identifiers', () => {
  const fx = fixture();
  fx.store.queue(queueInput());
  const raw = allFiles(fx.directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes('confidential payroll evidence'), false);
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(evidenceId), false);
});

test('signed claim requests are replay protected', () => {
  const fx = fixture();
  fx.store.queue(queueInput());
  const claim = signed({ limit: 1 }, 'claim', fx.clock.toISOString(), 'claim-nonce-0000000002');
  fx.store.claimSigned(claim.bytes, claim.headers);
  assert.throws(() => fx.store.claimSigned(claim.bytes, claim.headers), EvidenceAssuranceBundleAuthenticationError);
});

test('acknowledgement validates the claim token and removes sealed package bytes', () => {
  const fx = fixture();
  const queued = fx.store.queue(queueInput());
  const claim = signed({ limit: 1 }, 'claim', fx.clock.toISOString(), 'claim-nonce-0000000003');
  const job = fx.store.claimSigned(claim.bytes, claim.headers).bundles[0];
  const ackBody = { claimToken: job.claimToken, packageSha256: job.packageSha256 };
  const ack = signed(ackBody, `acknowledge:${queued.bundle.bundleId}`, fx.clock.toISOString(), 'ack-nonce-000000000001');
  const delivered = fx.store.acknowledgeSigned(queued.bundle.bundleId, ack.bytes, ack.headers);
  assert.equal(delivered.state, 'delivered');
  assert.equal(fx.store.list(tenantId)[0].state, 'delivered');
  const raw = allFiles(fx.directory).filter((path) => path.endsWith('.bundle')).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(job.sealedPackage.ciphertext), false);
});

test('expired assurance bundles can be resealed from a freshly verified source', () => {
  const fx = fixture({ bundleTtlMinutes: 5 });
  const first = fx.store.queue(queueInput());
  fx.clock = new Date(fx.clock.getTime() + 6 * 60_000);
  assert.equal(fx.store.list(tenantId)[0].state, 'expired');
  const replacement = fx.store.queue(queueInput());
  assert.equal(replacement.resealed, true);
  assert.equal(replacement.bundle.bundleId, first.bundle.bundleId);
  assert.equal(replacement.bundle.state, 'pending');
  assert.notEqual(replacement.bundle.packageSha256, first.bundle.packageSha256);
});

test('enabled environment construction requires dedicated keys and recipient configuration', () => {
  assert.throws(() => createEvidenceAssuranceBundleStoreFromEnvironment({ env: {
    WORKFORCE_AUDIT_ASSURANCE_BUNDLE_MODE: 'pull',
    WORKFORCE_AUDIT_ASSURANCE_BUNDLE_REQUIRED: 'true'
  } }), /encryption keys/);
});
