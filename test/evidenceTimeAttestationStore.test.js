import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceTimeAttestationAuthenticationError,
  EvidenceTimeAttestationIntegrityError,
  EvidenceTimeAttestationRequiredError,
  canonicalTimeAttestation,
  createEvidenceTimeAttestationStore
} from '../src/evidence/evidenceTimeAttestationStore.js';
import { createEvidenceTimeAttestationRegistry } from '../src/evidence/evidenceTimeAttestationRegistry.js';

const encryptionKey = Buffer.alloc(32, 83).toString('base64');
const tenantId = 'tenant-notary';
const archiveId = `ARC-${'a'.repeat(32)}`;
const evidenceId = `EVD-${'b'.repeat(32)}`;
const receiptSha256 = 'c'.repeat(64);
const objectEnvelopeSha256 = 'd'.repeat(64);
const nowValue = '2026-07-30T00:05:00.000Z';
const challenge = {
  tenantId,
  archiveId,
  receiptSha256,
  objectEnvelopeSha256,
  archivedAt: '2026-07-30T00:00:00.000Z',
  retentionUntil: '2033-07-30T00:00:00.000Z'
};

function authority() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function fixture({ minimumProviders = 1, requiredForDisposition = false } = {}) {
  const first = authority();
  const second = authority();
  const directory = mkdtempSync(join(tmpdir(), 'time-attestations-'));
  const store = createEvidenceTimeAttestationStore({
    mode: 'shared-file',
    requiredForDisposition,
    minimumProviders,
    directory,
    encryptionKeys: { n1: encryptionKey },
    encryptionPrimaryKeyId: 'n1',
    providers: {
      'authority-one': { keys: { k1: { algorithm: 'ed25519', publicKeyPem: first.publicKey } } },
      'authority-two': { keys: { k2: { algorithm: 'ed25519', publicKeyPem: second.publicKey } } }
    },
    resolveChallenge: () => challenge,
    now: () => new Date(nowValue),
    maxRecords: 100
  });
  return { store, directory, first, second };
}

function submission(providerId, keyId, privateKey, nonce, overrides = {}) {
  const input = {
    ...challenge,
    providerId,
    keyId,
    timestamp: nowValue,
    policyId: 'policy-qualified-time-v1',
    nonce,
    ...overrides
  };
  delete input.archivedAt;
  delete input.retentionUntil;
  const signature = sign(null, Buffer.from(canonicalTimeAttestation(input)), privateKey).toString('base64');
  return { ...input, signature };
}

function filesUnder(directory) {
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

test('accepts real Ed25519 time attestations and stores only encrypted records', () => {
  const { store, directory, first } = fixture();
  const input = submission('authority-one', 'k1', first.privateKey, 'nonce-authority-one-0001');
  const result = store.record(input);
  assert.equal(result.accepted, true);
  assert.equal(store.verifyArchive(tenantId, archiveId).quorumSatisfied, true);
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(archiveId), false);
  assert.equal(raw.includes('policy-qualified-time-v1'), false);
});

test('rejects invalid signatures and replayed authority nonces', () => {
  const { store, first, second } = fixture();
  const valid = submission('authority-one', 'k1', first.privateKey, 'nonce-replay-00000001');
  store.record(valid);
  const replay = submission('authority-one', 'k1', first.privateKey, 'nonce-replay-00000001', {
    policyId: 'policy-qualified-time-v2'
  });
  assert.throws(() => store.record(replay), EvidenceTimeAttestationAuthenticationError);
  const invalid = submission('authority-one', 'k1', second.privateKey, 'nonce-invalid-0000001');
  assert.throws(() => store.record(invalid), EvidenceTimeAttestationAuthenticationError);
});

test('counts distinct providers for quorum instead of multiple keys or records', () => {
  const { store, first, second } = fixture({ minimumProviders: 2 });
  store.record(submission('authority-one', 'k1', first.privateKey, 'nonce-quorum-one-0001'));
  assert.equal(store.verifyArchive(tenantId, archiveId).quorumSatisfied, false);
  store.record(submission('authority-two', 'k2', second.privateKey, 'nonce-quorum-two-0001'));
  const verified = store.verifyArchive(tenantId, archiveId);
  assert.equal(verified.quorumSatisfied, true);
  assert.equal(verified.distinctProviders, 2);
});

test('tampered encrypted attestation indexes fail closed', () => {
  const { store, directory, first } = fixture();
  store.record(submission('authority-one', 'k1', first.privateKey, 'nonce-tamper-0000001'));
  const indexPath = filesUnder(directory).find((path) => path.endsWith('time-attestations.evidence'));
  const envelope = JSON.parse(readFileSync(indexPath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(indexPath, JSON.stringify(envelope));
  assert.throws(() => store.verifyTenant(tenantId), EvidenceTimeAttestationIntegrityError);
});

test('registry-level disposition requires the configured authority quorum', () => {
  const { store, first, second } = fixture({ minimumProviders: 2, requiredForDisposition: true });
  const receipt = { archiveId, objectEnvelopeSha256 };
  const base = {
    verifyEvidencePreservation() {
      return {
        archiveId,
        receipt: {
          ...receipt,
          receiptId: 'PRR-1',
          evidenceId,
          evidenceVersion: 1,
          contentSha256: 'e'.repeat(64),
          sizeBytes: 10,
          retentionUntil: challenge.retentionUntil,
          archivedAt: challenge.archivedAt,
          signingKeyId: 'p1',
          signature: 'receipt-signature'
        }
      };
    },
    evidencePreservationStore: {
      verifiedForVersion() { return receipt; }
    },
    get() {
      return {
        evidenceId,
        status: 'active',
        retentionUntil: challenge.retentionUntil,
        versions: [{ version: 1, sha256: 'e'.repeat(64) }]
      };
    },
    list() { return []; },
    dispose() { return { status: 'disposed' }; },
    verify() { return { valid: true }; },
    health() { return { status: 'ready', required: false }; },
    tenantStatus() { return { status: 'ready' }; },
    evidencePreservationReceipts() { return []; }
  };
  const registry = createEvidenceTimeAttestationRegistry({ registry: base, timeAttestations: store });
  assert.throws(
    () => registry.dispose(tenantId, evidenceId, {}, {}),
    EvidenceTimeAttestationRequiredError
  );
  store.record(submission('authority-one', 'k1', first.privateKey, 'nonce-gate-one-000001'));
  assert.throws(
    () => registry.dispose(tenantId, evidenceId, {}, {}),
    EvidenceTimeAttestationRequiredError
  );
  store.record(submission('authority-two', 'k2', second.privateKey, 'nonce-gate-two-000001'));
  assert.equal(registry.dispose(tenantId, evidenceId, {}, {}).status, 'disposed');
});
