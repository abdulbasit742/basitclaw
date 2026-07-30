import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceAssuranceReceiptIntegrityError,
  EvidenceAssuranceReceiptSignatureError,
  createEvidenceAssuranceReceiptStore
} from '../src/evidence/evidenceAssuranceReceiptStore.js';

const tenantId = 'tenant-assurance-receipts';
const recipientId = 'external-auditor';
const encryptionKey = Buffer.alloc(32, 111).toString('base64');
const ed25519 = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), 'assurance-receipts-'));
  let clock = new Date('2026-07-30T02:00:00.000Z');
  const store = createEvidenceAssuranceReceiptStore({
    mode: 'shared-file',
    required: true,
    directory,
    encryptionKeys: { receipt: encryptionKey },
    encryptionPrimaryKeyId: 'receipt',
    recipients: {
      [recipientId]: {
        receiptKeys: {
          receipt1: { algorithm: 'ed25519', publicKeyPem: ed25519.publicKey }
        }
      }
    },
    maximumRecords: 100,
    clockSkewSeconds: 300,
    now: () => new Date(clock)
  });
  return {
    store,
    directory,
    get clock() { return clock; },
    set clock(value) { clock = new Date(value); }
  };
}

function receiptInput({ index = 1, claimedAt = '2026-07-30T01:59:00.000Z', receivedAt = '2026-07-30T02:00:00.000Z' } = {}) {
  const bundleId = `ASB-${index.toString(16).padStart(32, '0')}`;
  const packageSha256 = index.toString(16).padStart(64, '0');
  const canonical = [
    'basitclaw-assurance-delivery-receipt-v1',
    recipientId,
    bundleId,
    packageSha256,
    receivedAt,
    'receipt1'
  ].join('\n');
  return {
    tenantId,
    recipientId,
    bundleId,
    packageSha256,
    claimedAt,
    receivedAt,
    keyId: 'receipt1',
    signature: sign(null, Buffer.from(canonical), ed25519.privateKey).toString('base64')
  };
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

test('verifies an Ed25519 receipt and commits an encrypted hash-chained record', () => {
  const fx = fixture();
  const input = receiptInput();
  const result = fx.store.verifyAndRecord(input);
  assert.equal(result.duplicate, false);
  assert.match(result.receipt.receiptId, /^ADR-/);
  assert.equal(result.receipt.sequence, 1);
  assert.equal(result.receipt.previousHash, null);
  assert.equal(fx.store.get(tenantId, input.bundleId).recordHash, result.receipt.recordHash);
  assert.deepEqual(fx.store.verifyTenant(tenantId), {
    valid: true,
    tenantId,
    checkedReceipts: 1,
    chainHead: result.receipt.recordHash
  });

  const raw = allFiles(fx.directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(input.bundleId), false);
  assert.equal(raw.includes(input.packageSha256), false);
});

test('exact retries are idempotent and preserve the original receipt evidence', () => {
  const fx = fixture();
  const input = receiptInput();
  const first = fx.store.verifyAndRecord(input);
  const duplicate = fx.store.verifyAndRecord(input);
  assert.equal(duplicate.duplicate, true);
  assert.equal(duplicate.receipt.receiptId, first.receipt.receiptId);
  assert.equal(fx.store.list(tenantId).length, 1);
});

test('invalid signatures and receipt times fail closed before journal writes', () => {
  const fx = fixture();
  const invalid = receiptInput();
  invalid.signature = Buffer.alloc(64, 7).toString('base64');
  assert.throws(() => fx.store.verifyAndRecord(invalid), EvidenceAssuranceReceiptSignatureError);
  assert.equal(fx.store.list(tenantId).length, 0);

  const stale = receiptInput({
    index: 2,
    claimedAt: '2026-07-30T01:59:00.000Z',
    receivedAt: '2026-07-30T01:40:00.000Z'
  });
  assert.throws(() => fx.store.verifyAndRecord(stale), EvidenceAssuranceReceiptSignatureError);
  assert.equal(fx.store.list(tenantId).length, 0);
});

test('multiple receipts form a sequence-ordered chain', () => {
  const fx = fixture();
  const first = fx.store.verifyAndRecord(receiptInput({ index: 1 }));
  const second = fx.store.verifyAndRecord(receiptInput({ index: 2 }));
  assert.equal(second.receipt.sequence, 2);
  assert.equal(second.receipt.previousHash, first.receipt.recordHash);
  assert.equal(fx.store.verifyTenant(tenantId).checkedReceipts, 2);
});

test('tampered encrypted receipt ciphertext fails tenant verification', () => {
  const fx = fixture();
  fx.store.verifyAndRecord(receiptInput());
  const receiptPath = allFiles(fx.directory).find((path) => path.endsWith('.receipt'));
  const envelope = JSON.parse(readFileSync(receiptPath, 'utf8'));
  envelope.ciphertext = envelope.ciphertext.replace(/^./, envelope.ciphertext[0] === 'A' ? 'B' : 'A');
  writeFileSync(receiptPath, JSON.stringify(envelope));
  assert.throws(() => fx.store.verifyTenant(tenantId), EvidenceAssuranceReceiptIntegrityError);
});
