import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { createEvidenceAssuranceBundleStore } from '../src/evidence/evidenceAssuranceBundleStore.js';
import {
  EvidenceAssuranceReceiptSignatureError,
  createEvidenceAssuranceReceiptStore
} from '../src/evidence/evidenceAssuranceReceiptStore.js';

const tenantId = 'tenant-receipt-integration';
const evidenceId = `EVD-${'e'.repeat(32)}`;
const recipientId = 'external-auditor';
const bundleKey = Buffer.alloc(32, 101).toString('base64');
const receiptKey = Buffer.alloc(32, 102).toString('base64');
const hmacSecret = Buffer.alloc(48, 103);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const receiptSigner = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture({ required = true } = {}) {
  let clock = new Date('2026-07-30T03:00:00.000Z');
  const recipients = {
    [recipientId]: {
      keys: { h1: hmacSecret.toString('base64') },
      primaryPublicKeyId: 'rsa1',
      publicKeys: { rsa1: rsa.publicKey },
      receiptKeys: {
        receipt1: { algorithm: 'ed25519', publicKeyPem: receiptSigner.publicKey }
      }
    }
  };
  const receiptStore = createEvidenceAssuranceReceiptStore({
    mode: 'shared-file',
    required,
    directory: mkdtempSync(join(tmpdir(), 'assurance-receipt-integration-')),
    encryptionKeys: { receipt: receiptKey },
    encryptionPrimaryKeyId: 'receipt',
    recipients,
    maximumRecords: 100,
    clockSkewSeconds: 300,
    now: () => new Date(clock)
  });
  const store = createEvidenceAssuranceBundleStore({
    mode: 'pull',
    required: true,
    directory: mkdtempSync(join(tmpdir(), 'assurance-bundle-integration-')),
    encryptionKeys: { bundle: bundleKey },
    encryptionPrimaryKeyId: 'bundle',
    recipients,
    deliveryReceipts: receiptStore,
    bundleTtlMinutes: 60,
    claimLeaseMs: 30_000,
    maximumClaimBytes: 2_000_000,
    retention: 100,
    now: () => new Date(clock)
  });
  return { store, receiptStore, get clock() { return clock; }, set clock(value) { clock = new Date(value); } };
}

function queueInput() {
  const content = Buffer.from('recipient-signed delivery evidence');
  const evidence = {
    content: {
      filename: 'evidence.txt',
      mediaType: 'text/plain',
      sha256: sha256(content),
      sizeBytes: content.length,
      contentBase64: content.toString('base64')
    }
  };
  return {
    tenantId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256: evidence.content.sha256,
    recipientId,
    requestedBy: 'manager.one',
    purpose: 'External assurance review with signed delivery evidence',
    manifest: { format: 'basitclaw-assurance-bundle-manifest', version: 1, bundleDigest: sha256('receipt-manifest') },
    evidence
  };
}

function hmacSigned(body, operation, timestamp, nonce) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = [recipientId, 'h1', operation, timestamp, nonce, sha256(bytes)].join('\n');
  return {
    bytes,
    headers: {
      'x-basitclaw-recipient-id': recipientId,
      'x-basitclaw-recipient-key-id': 'h1',
      'x-basitclaw-recipient-timestamp': timestamp,
      'x-basitclaw-recipient-nonce': nonce,
      'x-basitclaw-recipient-signature': createHmac('sha256', hmacSecret).update(canonical).digest('base64')
    }
  };
}

function receipt(packageSha256, bundleId, receivedAt) {
  const canonical = [
    'basitclaw-assurance-delivery-receipt-v1',
    recipientId,
    bundleId,
    packageSha256,
    receivedAt,
    'receipt1'
  ].join('\n');
  return {
    receivedAt,
    keyId: 'receipt1',
    signature: sign(null, Buffer.from(canonical), receiptSigner.privateKey).toString('base64')
  };
}

function queueAndClaim(fx, nonceSuffix) {
  const queued = fx.store.queue(queueInput());
  const claim = hmacSigned({ limit: 1 }, 'claim', fx.clock.toISOString(), `claim-receipt-${nonceSuffix}-0001`);
  const job = fx.store.claimSigned(claim.bytes, claim.headers).bundles[0];
  return { queued, job };
}

test('required recipient signature is committed before sealed package deletion', () => {
  const fx = fixture();
  const { queued, job } = queueAndClaim(fx, 'ordering');
  const ackBody = {
    claimToken: job.claimToken,
    packageSha256: job.packageSha256,
    receipt: receipt(job.packageSha256, queued.bundle.bundleId, fx.clock.toISOString())
  };
  const ack = hmacSigned(ackBody, `acknowledge:${queued.bundle.bundleId}`, fx.clock.toISOString(), 'ack-receipt-ordering-0001');
  const delivered = fx.store.acknowledgeSigned(queued.bundle.bundleId, ack.bytes, ack.headers);
  assert.equal(delivered.state, 'delivered');
  assert.match(delivered.deliveryReceiptId, /^ADR-/);
  assert.equal(fx.receiptStore.get(tenantId, queued.bundle.bundleId).receiptId, delivered.deliveryReceiptId);
  assert.equal(fx.store.list(tenantId)[0].deliveryReceiptRecordHash, delivered.deliveryReceiptRecordHash);
});

test('missing required receipt leaves the claimed bundle undelivered', () => {
  const fx = fixture();
  const { queued, job } = queueAndClaim(fx, 'missing');
  const ackBody = { claimToken: job.claimToken, packageSha256: job.packageSha256 };
  const ack = hmacSigned(ackBody, `acknowledge:${queued.bundle.bundleId}`, fx.clock.toISOString(), 'ack-receipt-missing-0001');
  assert.throws(() => fx.store.acknowledgeSigned(queued.bundle.bundleId, ack.bytes, ack.headers), /required/);
  const current = fx.store.list(tenantId)[0];
  assert.equal(current.state, 'claimed');
  assert.equal(current.deliveryReceiptId, null);
  assert.equal(fx.receiptStore.get(tenantId, queued.bundle.bundleId), null);
});

test('invalid recipient signature never marks the bundle delivered', () => {
  const fx = fixture();
  const { queued, job } = queueAndClaim(fx, 'invalid');
  const invalidReceipt = receipt(job.packageSha256, queued.bundle.bundleId, fx.clock.toISOString());
  invalidReceipt.signature = Buffer.alloc(64, 9).toString('base64');
  const ackBody = { claimToken: job.claimToken, packageSha256: job.packageSha256, receipt: invalidReceipt };
  const ack = hmacSigned(ackBody, `acknowledge:${queued.bundle.bundleId}`, fx.clock.toISOString(), 'ack-receipt-invalid-0001');
  assert.throws(
    () => fx.store.acknowledgeSigned(queued.bundle.bundleId, ack.bytes, ack.headers),
    EvidenceAssuranceReceiptSignatureError
  );
  assert.equal(fx.store.list(tenantId)[0].state, 'claimed');
  assert.equal(fx.receiptStore.get(tenantId, queued.bundle.bundleId), null);
});

test('retry completes delivery after receipt journal commit survives an interrupted bundle update', () => {
  const fx = fixture();
  const { queued, job } = queueAndClaim(fx, 'recovery');
  const signedReceipt = receipt(job.packageSha256, queued.bundle.bundleId, fx.clock.toISOString());
  fx.receiptStore.verifyAndRecord({
    tenantId,
    recipientId,
    bundleId: queued.bundle.bundleId,
    packageSha256: job.packageSha256,
    claimedAt: fx.store.list(tenantId)[0].claimedAt,
    ...signedReceipt
  });

  const ackBody = { claimToken: job.claimToken, packageSha256: job.packageSha256, receipt: signedReceipt };
  const ack = hmacSigned(ackBody, `acknowledge:${queued.bundle.bundleId}`, fx.clock.toISOString(), 'ack-receipt-recovery-0001');
  const delivered = fx.store.acknowledgeSigned(queued.bundle.bundleId, ack.bytes, ack.headers);
  assert.equal(delivered.state, 'delivered');
  assert.equal(fx.receiptStore.list(tenantId).length, 1);
  assert.equal(delivered.deliveryReceiptId, fx.receiptStore.get(tenantId, queued.bundle.bundleId).receiptId);
});
