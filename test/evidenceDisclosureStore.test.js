import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  privateDecrypt
} from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceDisclosureApprovalError,
  EvidenceDisclosureIntegrityError,
  createEvidenceDisclosureStore
} from '../src/evidence/evidenceDisclosureStore.js';

const tenantId = 'tenant-disclosure';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const content = Buffer.from('confidential payroll control evidence');
const contentSha256 = createHash('sha256').update(content).digest('hex');
const encryptionKey = Buffer.alloc(32, 101).toString('base64');
const recipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const otherRecipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture(options = {}) {
  const directory = mkdtempSync(join(tmpdir(), 'evidence-disclosure-'));
  let current = new Date('2026-07-30T01:00:00.000Z');
  const resolverCalls = [];
  const store = createEvidenceDisclosureStore({
    mode: 'shared-file',
    directory,
    encryptionKeys: { d1: encryptionKey },
    encryptionPrimaryKeyId: 'd1',
    minimumApprovers: options.minimumApprovers ?? 2,
    maximumPackageBytes: options.maximumPackageBytes ?? 1_000_000,
    maximumTtlHours: 168,
    resolveEvidence(_tenant, selection) {
      resolverCalls.push({ ...selection });
      return {
        evidenceId,
        version: 1,
        filename: 'payroll.txt',
        mediaType: 'text/plain',
        contentSha256,
        sizeBytes: content.length,
        preservationArchiveId: `ARC-${'b'.repeat(32)}`,
        preservationReceiptSha256: 'c'.repeat(64),
        timeAttestationProviders: ['authority-a', 'authority-b'],
        content
      };
    },
    now: () => new Date(current)
  });
  return {
    store,
    directory,
    resolverCalls,
    setNow(value) { current = new Date(value); }
  };
}

function requestInput(overrides = {}) {
  return {
    recipientId: 'regulator-one',
    recipientKeyId: '2026-q3',
    recipientPublicKeyPem: recipient.publicKey,
    caseReference: 'REG-2026-0042',
    purpose: 'Controlled regulatory evidence disclosure',
    expiresAt: '2026-08-01T01:00:00.000Z',
    evidence: [{ evidenceId, version: 1 }],
    ...overrides
  };
}

function create(store, overrides = {}) {
  return store.createRequest(requestInput(overrides), {
    tenantId,
    actor: 'audit.manager'
  });
}

function approve(store, requestId, actor) {
  return store.approve(tenantId, requestId, {
    reason: 'Independent disclosure approval completed',
    confirmation: `APPROVE DISCLOSURE ${requestId}`
  }, { actor });
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

function decryptPackage(envelope, privateKey) {
  const key = privateDecrypt({
    key: privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from(envelope.wrappedKey, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAAD(Buffer.from(envelope.aad, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.authTag, 'base64'));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, 'base64')),
    decipher.final()
  ]).toString('utf8'));
}

test('requires requester separation and two distinct approvals', () => {
  const { store } = fixture();
  const request = create(store).request;
  assert.throws(() => approve(store, request.requestId, 'audit.manager'), EvidenceDisclosureApprovalError);
  assert.equal(approve(store, request.requestId, 'compliance.one').packaged, false);
  assert.throws(() => approve(store, request.requestId, 'compliance.one'), EvidenceDisclosureApprovalError);
  const result = approve(store, request.requestId, 'compliance.two');
  assert.equal(result.packaged, true);
  assert.equal(result.request.state, 'packaged');
});

test('only the recipient private key decrypts the sealed manifest', () => {
  const { store, resolverCalls } = fixture();
  const request = create(store).request;
  approve(store, request.requestId, 'compliance.one');
  approve(store, request.requestId, 'compliance.two');
  const envelope = store.sealedPackage(tenantId, request.requestId);
  const manifest = decryptPackage(envelope, recipient.privateKey);
  assert.equal(manifest.format, 'basitclaw-evidence-disclosure-manifest');
  assert.equal(manifest.evidence[0].evidenceId, evidenceId);
  assert.equal(Buffer.from(manifest.evidence[0].contentBase64, 'base64').toString(), content.toString());
  assert.deepEqual(manifest.evidence[0].timeAttestationProviders, ['authority-a', 'authority-b']);
  assert.equal(resolverCalls.length, 2);
  assert.throws(() => decryptPackage(envelope, otherRecipient.privateKey));
});

test('indexes and sealed packages contain no operational plaintext', () => {
  const { store, directory } = fixture();
  const request = create(store).request;
  approve(store, request.requestId, 'compliance.one');
  approve(store, request.requestId, 'compliance.two');
  const raw = filesUnder(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  for (const sensitive of [tenantId, evidenceId, 'regulator-one', 'REG-2026-0042', content.toString()]) {
    assert.equal(raw.includes(sensitive), false);
  }
  assert.equal(store.verifyTenant(tenantId).checkedPackages, 1);
});

test('revocation, expiry and byte limits fail closed', () => {
  const { store, setNow } = fixture();
  const request = create(store).request;
  approve(store, request.requestId, 'compliance.one');
  approve(store, request.requestId, 'compliance.two');
  store.revoke(tenantId, request.requestId, {
    reason: 'Recipient authority was withdrawn before delivery',
    confirmation: `REVOKE DISCLOSURE ${request.requestId}`
  }, { actor: 'compliance.admin' });
  assert.throws(() => store.sealedPackage(tenantId, request.requestId));

  const expiring = create(store, {
    caseReference: 'REG-2026-0043',
    expiresAt: '2026-07-30T02:00:00.000Z'
  }).request;
  setNow('2026-07-30T03:00:00.000Z');
  assert.equal(store.get(tenantId, expiring.requestId).state, 'expired');
  assert.throws(() => approve(store, expiring.requestId, 'compliance.one'));

  const small = fixture({ maximumPackageBytes: 10 }).store;
  const limited = create(small).request;
  approve(small, limited.requestId, 'compliance.one');
  assert.throws(() => approve(small, limited.requestId, 'compliance.two'));
  assert.equal(small.get(tenantId, limited.requestId).approvals.length, 1);
});

test('sealed package tampering fails integrity verification', () => {
  const { store, directory } = fixture();
  const request = create(store).request;
  approve(store, request.requestId, 'compliance.one');
  approve(store, request.requestId, 'compliance.two');
  const packagePath = filesUnder(directory).find((path) => path.endsWith('.sealed'));
  const envelope = JSON.parse(readFileSync(packagePath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(packagePath, JSON.stringify(envelope));
  assert.throws(() => store.verifyTenant(tenantId), EvidenceDisclosureIntegrityError);
});
