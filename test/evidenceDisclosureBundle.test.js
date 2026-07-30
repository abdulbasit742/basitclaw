import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceDisclosureIntegrityError,
  createEvidenceDisclosureBundleStore
} from '../src/evidence/evidenceDisclosureBundleStore.js';
import {
  EvidenceDisclosureVerificationError,
  verifyAndDecryptDisclosurePackage
} from '../src/evidence/evidenceDisclosureVerifier.js';

const tenantId = 'tenant-disclosure';
const evidenceId = `EVD-${'d'.repeat(32)}`;
const indexKey = Buffer.alloc(32, 81).toString('base64');
const recipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const wrongRecipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const enterprise = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'disclosure-'));
  const store = createEvidenceDisclosureBundleStore({
    mode: 'shared-file',
    directory,
    indexKeys: { index: indexKey },
    indexPrimaryKeyId: 'index',
    recipients: {
      'external-auditor': {
        primaryKeyId: 'recipient-1',
        publicKeys: { 'recipient-1': recipient.publicKey }
      }
    },
    signingKeys: { 'enterprise-1': { privateKey: enterprise.privateKey } },
    signingPrimaryKeyId: 'enterprise-1',
    now: () => new Date('2026-07-30T02:00:00.000Z')
  });
  return { store, directory };
}

function payloadBody() {
  return {
    tenantReference: 'a'.repeat(64),
    evidence: {
      evidenceReference: evidenceId,
      status: 'active',
      currentVersion: 1,
      retentionUntil: '2033-07-30T00:00:00.000Z',
      legalHoldActive: false,
      filenameIncluded: false,
      versions: [{
        version: 1,
        filename: null,
        mediaType: 'text/csv',
        sizeBytes: 21,
        contentSha256: 'b'.repeat(64),
        screening: { status: 'clean', findings: [] },
        externalScans: [{ providerId: 'managed-av', verdict: 'clean' }],
        preservationReceipt: { archiveId: `ARC-${'c'.repeat(32)}` },
        timeAttestations: [{ providerId: 'qualified-tsa-a', governance: { operationallyAcceptable: true } }],
        timeAttestationVerification: { operationalQuorumSatisfied: true }
      }]
    },
    integrity: {
      registryVerification: { valid: true },
      versionCount: 1,
      allVersionsPreserved: true,
      allVersionsTimeAttested: true,
      allVersionsOperationallyAcceptable: true,
      notaryGovernanceEvaluated: true,
      rawEvidenceIncluded: false
    }
  };
}

function create(store, overrides = {}) {
  return store.create({
    tenantId,
    evidenceId,
    recipientId: 'external-auditor',
    idempotencyKey: 'annual-audit-2026-001',
    purpose: 'Independent workforce controls audit disclosure',
    expiresAt: '2026-08-30T02:00:00.000Z',
    payloadBody: payloadBody(),
    ...overrides
  }, { actor: 'manager.one' });
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

test('creates recipient-encrypted signed packages with no plaintext evidence metadata on disk', () => {
  const { store, directory } = fixture();
  const result = create(store);
  assert.equal(result.created, true);
  assert.equal(result.bundle.rawEvidenceIncluded, false);
  assert.equal(store.verify(tenantId, result.bundle.bundleId).valid, true);
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(evidenceId), false);
  assert.equal(raw.includes('Independent workforce controls audit disclosure'), false);
  assert.equal(raw.includes('managed-av'), false);
});

test('offline verifier authenticates, decrypts and validates the metadata-only manifest', () => {
  const { store } = fixture();
  const created = create(store);
  const packageValue = store.packageFor(tenantId, created.bundle.bundleId);
  const verified = verifyAndDecryptDisclosurePackage(packageValue, {
    recipientPrivateKey: recipient.privateKey,
    enterprisePublicKeys: { 'enterprise-1': enterprise.publicKey },
    now: () => new Date('2026-07-31T00:00:00.000Z')
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.evidenceReference, evidenceId);
  assert.equal(verified.versionCount, 1);
  assert.equal(verified.payload.policy.rawEvidenceIncluded, false);
  assert.equal(JSON.stringify(verified.payload).includes('contentBase64'), false);
});

test('wrong recipient keys and ciphertext tampering fail closed', () => {
  const { store } = fixture();
  const created = create(store);
  const packageValue = store.packageFor(tenantId, created.bundle.bundleId);
  assert.throws(() => verifyAndDecryptDisclosurePackage(packageValue, {
    recipientPrivateKey: wrongRecipient.privateKey,
    enterprisePublicKeys: { 'enterprise-1': enterprise.publicKey },
    now: () => new Date('2026-07-31T00:00:00.000Z')
  }), EvidenceDisclosureVerificationError);
  const tampered = { ...packageValue, ciphertext: packageValue.ciphertext.replace(/^./, packageValue.ciphertext[0] === 'A' ? 'B' : 'A') };
  assert.throws(() => verifyAndDecryptDisclosurePackage(tampered, {
    recipientPrivateKey: recipient.privateKey,
    enterprisePublicKeys: { 'enterprise-1': enterprise.publicKey },
    now: () => new Date('2026-07-31T00:00:00.000Z')
  }), EvidenceDisclosureVerificationError);
});

test('deterministic idempotency returns the original record and unknown recipients fail validation', () => {
  const { store } = fixture();
  const first = create(store);
  const duplicate = create(store);
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.bundle.bundleId, first.bundle.bundleId);
  assert.throws(() => create(store, { recipientId: 'another-recipient' }), /recipientId is not configured/);
});

test('tenant isolation and package-record pairing are enforced', () => {
  const { store, directory } = fixture();
  const created = create(store);
  assert.deepEqual(store.list('tenant-other'), []);
  assert.throws(() => store.packageFor('tenant-other', created.bundle.bundleId), EvidenceDisclosureIntegrityError);
  const recordPath = filesUnder(directory).find((path) => path.endsWith('.record'));
  writeFileSync(recordPath, `${JSON.stringify({ invalid: true })}\n`);
  assert.throws(() => store.verify(tenantId, created.bundle.bundleId), EvidenceDisclosureIntegrityError);
});

test('expired packages are rejected unless historical review is explicitly enabled', () => {
  const { store } = fixture();
  const created = create(store);
  const packageValue = store.packageFor(tenantId, created.bundle.bundleId);
  assert.throws(() => verifyAndDecryptDisclosurePackage(packageValue, {
    recipientPrivateKey: recipient.privateKey,
    enterprisePublicKeys: { 'enterprise-1': enterprise.publicKey },
    now: () => new Date('2026-09-01T00:00:00.000Z')
  }), /expired/);
  assert.equal(verifyAndDecryptDisclosurePackage(packageValue, {
    recipientPrivateKey: recipient.privateKey,
    enterprisePublicKeys: { 'enterprise-1': enterprise.publicKey },
    now: () => new Date('2026-09-01T00:00:00.000Z'),
    allowExpired: true
  }).valid, true);
});
