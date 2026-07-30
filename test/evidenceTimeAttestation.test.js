import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceTimeAttestationAuthenticationError,
  EvidenceTimeAttestationRequiredError,
  canonicalTimeAttestation,
  createEvidenceTimeAttestationStore
} from '../src/evidence/evidenceTimeAttestationStore.js';
import { createEvidenceTimeAttestationRegistry } from '../src/evidence/evidenceTimeAttestationRegistry.js';

const tenantId = 'tenant-notary';
const archiveId = `ARC-${'a'.repeat(32)}`;
const evidenceId = `EVD-${'b'.repeat(32)}`;
const receiptSha256 = 'c'.repeat(64);
const objectEnvelopeSha256 = 'd'.repeat(64);
const archivedAt = '2026-07-30T00:00:00.000Z';
const retentionUntil = '2033-07-30T00:00:00.000Z';
const encryptionKey = Buffer.alloc(32, 91).toString('base64');

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

const authorityA = keyPair();
const authorityB = keyPair();

function challenge() {
  return { tenantId, archiveId, receiptSha256, objectEnvelopeSha256, archivedAt, retentionUntil };
}

function storeFixture({ minimumProviders = 1 } = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'evidence-time-attestation-'));
  let current = new Date('2026-07-30T00:10:00.000Z');
  const store = createEvidenceTimeAttestationStore({
    mode: 'shared-file',
    requiredForDisposition: true,
    minimumProviders,
    directory,
    encryptionKeys: { notary: encryptionKey },
    encryptionPrimaryKeyId: 'notary',
    providers: {
      'authority-a': { keys: { 'key-a': { algorithm: 'ed25519', publicKeyPem: authorityA.publicKey } } },
      'authority-b': { keys: { 'key-b': { algorithm: 'ed25519', publicKeyPem: authorityB.publicKey } } }
    },
    resolveChallenge: () => challenge(),
    now: () => new Date(current)
  });
  return { store, directory, setNow: (value) => { current = new Date(value); } };
}

function submission(providerId, keyId, privateKey, nonce, overrides = {}) {
  const body = {
    tenantId,
    archiveId,
    providerId,
    keyId,
    receiptSha256,
    objectEnvelopeSha256,
    timestamp: '2026-07-30T00:05:00.000Z',
    policyId: 'independent-time-v1',
    nonce,
    ...overrides
  };
  body.signature = sign(null, Buffer.from(canonicalTimeAttestation(body)), privateKey).toString('base64');
  return body;
}

function allFiles(directory) {
  const files = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      entry.isDirectory() ? walk(child) : files.push(child);
    }
  };
  walk(directory);
  return files;
}

test('accepts real Ed25519 authority signatures and stores only encrypted indexes', () => {
  const { store, directory } = storeFixture();
  const first = store.record(submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0001'));
  assert.equal(first.accepted, true);
  assert.equal(store.verifyArchive(tenantId, archiveId).quorumSatisfied, true);
  assert.equal(store.verifyTenant(tenantId).checkedAttestations, 1);
  const raw = allFiles(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(archiveId), false);
  assert.equal(raw.includes('authority-a'), false);
  assert.equal(store.health().asymmetricSignatures, true);
});

test('exact duplicate is idempotent but reused nonce or challenge tampering fails closed', () => {
  const { store } = storeFixture();
  const original = submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0002');
  assert.equal(store.record(original).accepted, true);
  assert.equal(store.record(original).duplicate, true);
  assert.throws(
    () => store.record(submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0002', { policyId: 'different-policy' })),
    EvidenceTimeAttestationAuthenticationError
  );
  assert.throws(
    () => store.record(submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0003', { receiptSha256: 'e'.repeat(64) })),
    EvidenceTimeAttestationAuthenticationError
  );
});

test('quorum counts distinct authorities and verifies the encrypted hash chain', () => {
  const { store } = storeFixture({ minimumProviders: 2 });
  store.record(submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0004'));
  assert.equal(store.verifyArchive(tenantId, archiveId).quorumSatisfied, false);
  store.record(submission('authority-b', 'key-b', authorityB.privateKey, 'nonce-authority-b-0001'));
  const result = store.verifyArchive(tenantId, archiveId);
  assert.equal(result.quorumSatisfied, true);
  assert.deepEqual(result.providerIds, ['authority-a', 'authority-b']);
  assert.equal(store.verifyTenant(tenantId).headSequence, 2);
});

test('registry blocks disposition until every preservation archive has authority quorum', () => {
  const { store } = storeFixture({ minimumProviders: 2 });
  let disposed = false;
  const receipt = {
    receiptId: `PRR-${'f'.repeat(32)}`,
    archiveId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256: '1'.repeat(64),
    sizeBytes: 10,
    objectEnvelopeSha256,
    retentionUntil,
    archivedAt,
    immutabilityMode: 'backend-confirmed-write-once',
    signingKeyId: 'receipt-key',
    signature: Buffer.alloc(32, 3).toString('base64')
  };
  const registry = createEvidenceTimeAttestationRegistry({
    registry: {
      evidencePreservationEnabled: true,
      evidencePreservationStore: {
        verifiedForVersion() { return receipt; }
      },
      verifyEvidencePreservation() { return { valid: true, archiveId, receipt }; },
      evidencePreservationReceipts() { return [receipt]; },
      get() { return { evidenceId, status: 'retained', retentionUntil, versions: [{ version: 1, sha256: receipt.contentSha256 }] }; },
      list() { return []; },
      dispose() { disposed = true; return { status: 'disposed' }; },
      verify() { return { valid: true }; },
      health() { return { status: 'ready', required: true }; },
      tenantStatus() { return { status: 'ready' }; }
    },
    timeAttestations: store
  });
  assert.throws(() => registry.dispose(tenantId, evidenceId, {}, {}), EvidenceTimeAttestationRequiredError);
  store.record(submission('authority-a', 'key-a', authorityA.privateKey, 'nonce-authority-a-0005'));
  assert.throws(() => registry.dispose(tenantId, evidenceId, {}, {}), EvidenceTimeAttestationRequiredError);
  store.record(submission('authority-b', 'key-b', authorityB.privateKey, 'nonce-authority-b-0002'));
  assert.equal(registry.dispose(tenantId, evidenceId, {}, {}).status, 'disposed');
  assert.equal(disposed, true);
});
