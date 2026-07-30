import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createDecipheriv,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  verify
} from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceDisclosureExpiredError,
  EvidenceDisclosureIntegrityError,
  EvidenceDisclosureLimitError,
  EvidenceDisclosureRevokedError,
  createEvidenceDisclosureStore
} from '../src/evidence/evidenceDisclosureStore.js';

const tenantId = 'tenant-disclosure';
function fixture() {
  const recipient = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const signer = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const directory = mkdtempSync(join(tmpdir(), 'evidence-disclosure-'));
  let current = new Date('2030-01-01T00:00:00.000Z');
  const store = createEvidenceDisclosureStore({
    mode: 'shared-file', directory,
    metadataKeys: { metadata: Buffer.alloc(32, 121).toString('base64') },
    metadataPrimaryKeyId: 'metadata',
    signingPrivateKeys: { signing: signer.privateKey },
    signingPrimaryKeyId: 'signing',
    maximumPackageBytes: 2_000_000,
    now: () => new Date(current)
  });
  return { store, directory, recipient, signer, setNow(value) { current = new Date(value); } };
}
function input(recipient, overrides = {}) {
  return {
    tenantId,
    recipientKeyId: 'regulator-2029',
    recipientPublicKeyPem: recipient.publicKey,
    expiresAt: '2031-01-01T00:00:00.000Z',
    maximumDownloads: 2,
    purpose: 'Regulatory disclosure for external audit review',
    itemCount: 1,
    payload: {
      format: 'basitclaw-evidence-disclosure-payload-v1',
      tenantScope: 'tenant-sha256:example',
      evidence: [{ evidenceId: `EVD-${'a'.repeat(32)}`, version: 1, contentBase64: Buffer.from('secret payroll evidence').toString('base64') }]
    },
    ...overrides
  };
}
function files(directory) {
  const output = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) walk(child); else output.push(child);
    }
  };
  walk(directory);
  return output;
}
function decryptPackage(value, privateKey) {
  const dataKey = privateDecrypt({ key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, Buffer.from(value.wrappedKey, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', dataKey, Buffer.from(value.iv, 'base64'));
  decipher.setAAD(Buffer.from(`${value.format}:${value.packageId}:${value.recipientKeyFingerprint}`));
  decipher.setAuthTag(Buffer.from(value.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(value.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }

test('creates a recipient-encrypted package with a valid Ed25519 manifest signature', () => {
  const { store, directory, recipient, signer } = fixture();
  const created = store.create(input(recipient), { actor: 'manager.one' });
  const downloaded = store.download(tenantId, created.disclosure.packageId);
  const { signature, ...unsigned } = downloaded.package;
  assert.equal(verify(null, Buffer.from(stableStringify(unsigned)), createPublicKey(signer.publicKey), Buffer.from(signature, 'base64')), true);
  const payload = decryptPackage(downloaded.package, recipient.privateKey);
  assert.equal(Buffer.from(payload.evidence[0].contentBase64, 'base64').toString(), 'secret payroll evidence');
  const raw = files(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes('secret payroll evidence'), false);
  assert.equal(raw.includes(tenantId), false);
});

test('exact duplicate requests are idempotent and preserve the original actor', () => {
  const { store, recipient } = fixture();
  const first = store.create(input(recipient), { actor: 'manager.one' });
  const duplicate = store.create(input(recipient), { actor: 'manager.two' });
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.disclosure.packageId, first.disclosure.packageId);
  assert.equal(duplicate.disclosure.createdBy, 'manager.one');
});

test('wrong recipient key cannot decrypt the disclosure payload', () => {
  const { store, recipient } = fixture();
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const created = store.create(input(recipient), { actor: 'manager.one' });
  assert.throws(() => decryptPackage(store.download(tenantId, created.disclosure.packageId).package, other.privateKey));
});

test('tampered package ciphertext fails signature and metadata verification', () => {
  const { store, directory, recipient } = fixture();
  const created = store.create(input(recipient), { actor: 'manager.one' });
  const path = files(directory).find((candidate) => candidate.endsWith(`${created.disclosure.packageId}.json`));
  const value = JSON.parse(readFileSync(path, 'utf8'));
  value.ciphertext = value.ciphertext.replace(/^./, value.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(path, JSON.stringify(value));
  assert.throws(() => store.verify(tenantId, created.disclosure.packageId), EvidenceDisclosureIntegrityError);
});

test('download limits, expiry and revocation fail closed', () => {
  const { store, recipient, setNow } = fixture();
  const limited = store.create(input(recipient, { maximumDownloads: 1 }), { actor: 'manager.one' });
  store.download(tenantId, limited.disclosure.packageId);
  assert.throws(() => store.download(tenantId, limited.disclosure.packageId), EvidenceDisclosureLimitError);
  const expiring = store.create(input(recipient, { purpose: 'A distinct expiring regulatory disclosure package' }), { actor: 'manager.one' });
  setNow('2032-01-01T00:00:00.000Z');
  assert.throws(() => store.download(tenantId, expiring.disclosure.packageId), EvidenceDisclosureExpiredError);
  setNow('2030-01-02T00:00:00.000Z');
  const revoked = store.create(input(recipient, { purpose: 'A distinct revoked regulatory disclosure package' }), { actor: 'manager.one' });
  store.revoke(tenantId, revoked.disclosure.packageId, { actor: 'admin.one', reason: 'Recipient mandate was withdrawn before delivery' });
  assert.throws(() => store.download(tenantId, revoked.disclosure.packageId), EvidenceDisclosureRevokedError);
});
