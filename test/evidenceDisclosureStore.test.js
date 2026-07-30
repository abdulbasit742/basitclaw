import test from 'node:test';
import assert from 'node:assert/strict';
import {
  constants,
  createDecipheriv,
  createHmac,
  generateKeyPairSync,
  privateDecrypt
} from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceDisclosureAuthenticationError,
  createEvidenceDisclosureStore
} from '../src/evidence/evidenceDisclosureStore.js';
import { sha256 } from '../src/evidence/evidenceCrypto.js';

const tenantId = 'tenant-disclosure';
const evidenceId = `EVD-${'a'.repeat(32)}`;
const content = Buffer.from('confidential workforce audit evidence');
const contentSha256 = sha256(content);
const encryptionKey = Buffer.alloc(32, 41).toString('base64');
const hmacSecret = Buffer.alloc(48, 42);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture(overrides = {}) {
  let current = new Date('2026-07-30T01:00:00.000Z');
  const directory = mkdtempSync(join(tmpdir(), 'evidence-disclosure-'));
  const store = createEvidenceDisclosureStore({
    mode: 'shared-file',
    directory,
    encryptionKeys: { disclosure: encryptionKey },
    encryptionPrimaryKeyId: 'disclosure',
    recipients: {
      'regulator-one': {
        publicKeyId: 'rsa-2026-q3',
        publicKeyPem: rsa.publicKey,
        hmacKeys: { h1: hmacSecret.toString('base64') },
        allowedZones: ['pk-primary', 'eu-regulated']
      }
    },
    tenantResidencyZones: { [tenantId]: ['pk-primary'] },
    approvalQuorum: 2,
    claimLeaseMs: 60_000,
    now: () => new Date(current),
    ...overrides
  });
  return {
    store,
    directory,
    now: () => new Date(current),
    advance(ms) { current = new Date(current.getTime() + ms); }
  };
}

function requestInput(overrides = {}) {
  return {
    tenantId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256,
    sizeBytes: content.length,
    recipientId: 'regulator-one',
    residencyZone: 'pk-primary',
    purpose: 'Provide evidence for an authorised regulatory examination',
    expiresAt: '2026-07-31T01:00:00.000Z',
    ...overrides
  };
}

function contentProvider() {
  return { content, filename: 'workforce-audit.txt', mediaType: 'text/plain' };
}

function signed(body, now, nonce) {
  const bytes = Buffer.from(JSON.stringify(body));
  const timestamp = now.toISOString();
  const canonical = `regulator-one\nh1\n${timestamp}\n${nonce}\n${sha256(bytes)}`;
  return {
    bytes,
    headers: {
      'x-basitclaw-recipient-id': 'regulator-one',
      'x-basitclaw-recipient-key-id': 'h1',
      'x-basitclaw-recipient-timestamp': timestamp,
      'x-basitclaw-recipient-nonce': nonce,
      'x-basitclaw-recipient-signature': createHmac('sha256', hmacSecret).update(canonical).digest('hex')
    }
  };
}

function allFiles(directory) {
  const rows = [];
  const walk = (path) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) walk(child);
      else rows.push(child);
    }
  };
  walk(directory);
  return rows;
}

function decryptPackage(pkg) {
  const key = privateDecrypt({
    key: rsa.privateKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  }, Buffer.from(pkg.wrappedKey, 'base64'));
  const {
    algorithm: _algorithm,
    iv,
    tag,
    ciphertext,
    wrappedKey: _wrappedKey,
    publicKeyId: _publicKeyId,
    ...metadata
  } = pkg;
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64'));
  decipher.setAAD(Buffer.from(stableStringify(metadata)));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]);
}

function approveToSeal(store) {
  const requested = store.request(requestInput(), { actor: 'manager.requester', role: 'audit_manager' });
  assert.throws(
    () => store.approve(tenantId, requested.disclosureId, {
      actor: 'manager.requester', role: 'audit_manager', contentProvider
    }),
    /requester cannot approve/
  );
  const first = store.approve(tenantId, requested.disclosureId, {
    actor: 'manager.approver-one', role: 'audit_manager', contentProvider
  });
  assert.equal(first.state, 'requested');
  assert.equal(first.approvals.length, 1);
  const second = store.approve(tenantId, requested.disclosureId, {
    actor: 'admin.approver-two', role: 'compliance_admin', contentProvider
  });
  assert.equal(second.state, 'sealed');
  assert.equal(second.approvals.length, 2);
  return second;
}

test('requires two distinct approvals and decrypts only with the recipient private key', () => {
  const { store, directory, now } = fixture();
  const sealed = approveToSeal(store);
  const claim = signed({ tenantId, limit: 1 }, now(), 'recipient-claim-nonce-0001');
  const result = store.claimSigned(claim.bytes, claim.headers);
  assert.equal(result.jobs.length, 1);
  assert.equal(result.jobs[0].disclosureId, sealed.disclosureId);
  assert.deepEqual(decryptPackage(result.jobs[0].package), content);
  const raw = allFiles(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(content.toString('utf8')), false);
  assert.equal(raw.includes(tenantId), false);
  assert.equal(store.verifyTenant(tenantId).valid, true);
});

test('rejects recipient replay before returning another sealed package', () => {
  const { store, now } = fixture();
  approveToSeal(store);
  const request = signed({ tenantId, limit: 1 }, now(), 'recipient-replay-nonce-0001');
  store.claimSigned(request.bytes, request.headers);
  assert.throws(
    () => store.claimSigned(request.bytes, request.headers),
    EvidenceDisclosureAuthenticationError
  );
});

test('enforces residency zones before any disclosure record is written', () => {
  const { store } = fixture();
  assert.throws(
    () => store.request(requestInput({ residencyZone: 'eu-regulated' }), {
      actor: 'manager.requester', role: 'audit_manager'
    }),
    /not permitted for this tenant/
  );
  assert.equal(store.report(tenantId).total, 0);
});

test('acknowledgement removes sealed package bytes and records a terminal chain event', () => {
  const { store, directory, now } = fixture();
  const sealed = approveToSeal(store);
  const claimRequest = signed({ tenantId, limit: 1 }, now(), 'recipient-claim-nonce-0002');
  const job = store.claimSigned(claimRequest.bytes, claimRequest.headers).jobs[0];
  const acknowledge = signed({ tenantId, claimToken: job.claimToken }, now(), 'recipient-ack-nonce-0002');
  const result = store.acknowledgeSigned(sealed.disclosureId, acknowledge.bytes, acknowledge.headers);
  assert.equal(result.state, 'acknowledged');
  assert.equal(result.eventCount, 6);
  const raw = allFiles(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(job.package.ciphertext), false);
  assert.equal(raw.includes(job.claimToken), false);
  assert.equal(store.verifyTenant(tenantId).checkedRecords, 1);
});

test('revocation prevents recipient claim and preserves governance reporting', () => {
  const { store, now } = fixture();
  const sealed = approveToSeal(store);
  const revoked = store.revoke(tenantId, sealed.disclosureId, {
    actor: 'admin.revoker',
    reason: 'Recipient authority was withdrawn before delivery'
  });
  assert.equal(revoked.state, 'revoked');
  const request = signed({ tenantId, limit: 10 }, now(), 'recipient-claim-nonce-0003');
  assert.equal(store.claimSigned(request.bytes, request.headers).jobs.length, 0);
  assert.equal(store.report(tenantId).byState.revoked, 1);
});

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
