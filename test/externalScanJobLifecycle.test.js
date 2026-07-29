import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sha256 } from '../src/evidence/evidenceCrypto.js';
import { createExternalScanJobOutbox } from '../src/evidence/externalScanJobOutbox.js';
import {
  ExternalScanClaimBudgetError,
  createExternalScanJobJanitor,
  createExternalScanJobLifecycle,
  normaliseProviderDeliveryKeys
} from '../src/evidence/externalScanJobLifecycle.js';

const evidenceKey = Buffer.alloc(32, 51).toString('base64');
const providerSecret = Buffer.alloc(48, 63);
const currentIso = '2026-07-30T02:00:00.000Z';
const firstRsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const secondRsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function contentRecord(overrides = {}) {
  const content = Buffer.from('quarantined evidence bytes for expiry lifecycle');
  return {
    tenantId: 'tenant-a',
    evidenceId: 'EVD-fedcba9876543210fedcba9876543210',
    version: 1,
    filename: 'quarantine.bin',
    mediaType: 'application/octet-stream',
    contentSha256: sha256(content),
    sizeBytes: content.length,
    content,
    ...overrides
  };
}

function providers() {
  return {
    'managed-av': {
      keys: { h1: providerSecret.toString('base64') },
      publicKeys: { old: firstRsa.publicKey, current: secondRsa.publicKey }
    }
  };
}

function createFixture({ directory, now, jobTtlMinutes = 1, maxClaimBytes = 25_000_000, maximumEvidenceBytes = 10_000_000 } = {}) {
  const outbox = createExternalScanJobOutbox({
    mode: 'pull', required: true, directory,
    evidenceKeys: { k1: evidenceKey }, evidencePrimaryKeyId: 'k1', providers: providers(),
    jobTtlMinutes, claimLeaseMs: 10_000, completedRetention: 100, deadLetterRetention: 100,
    clockSkewSeconds: 300, now
  });
  const janitor = createExternalScanJobJanitor({
    directory, evidenceKeys: { k1: evidenceKey }, evidencePrimaryKeyId: 'k1',
    deadLetterRetention: 100, now
  });
  return createExternalScanJobLifecycle({ outbox, janitor, maxClaimBytes, maximumEvidenceBytes });
}

function signedBody(body, nonce, timestamp = currentIso) {
  const bytes = Buffer.from(JSON.stringify(body));
  const canonical = `managed-av\nh1\n${timestamp}\n${nonce}\n${sha256(bytes)}`;
  return {
    bytes,
    headers: {
      'x-basitclaw-scan-provider': 'managed-av',
      'x-basitclaw-scan-key-id': 'h1',
      'x-basitclaw-scan-timestamp': timestamp,
      'x-basitclaw-scan-nonce': nonce,
      'x-basitclaw-scan-signature': createHmac('sha256', providerSecret).update(canonical).digest('hex')
    }
  };
}

test('expired pending jobs move to dead letter during lifecycle maintenance', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-lifecycle-pending-'));
  let clock = new Date(currentIso);
  const jobs = createFixture({ directory, now: () => new Date(clock) });
  jobs.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  clock = new Date(clock.getTime() + 61_000);
  const status = jobs.tenantStatus('tenant-a');
  assert.equal(status.pending, 0);
  assert.equal(status.deadLetters, 1);
  assert.equal(jobs.list('tenant-a')[0].result.reasonCode, 'job_expired');
});

test('delivered jobs without a timely attestation expire to dead letter', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-lifecycle-delivered-'));
  let clock = new Date(currentIso);
  const jobs = createFixture({ directory, now: () => new Date(clock) });
  jobs.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  const claim = signedBody({ limit: 1 }, 'nonce-0000000000001001');
  const claimed = jobs.claimSigned(claim.bytes, claim.headers).jobs[0];
  const ack = signedBody({ claimToken: claimed.claimToken }, 'nonce-0000000000001002');
  assert.equal(jobs.acknowledgeSigned(claimed.jobId, ack.bytes, ack.headers).state, 'delivered');
  clock = new Date(clock.getTime() + 61_000);
  const row = jobs.list('tenant-a')[0];
  assert.equal(row.state, 'dead-letter');
  assert.equal(row.result.reasonCode, 'attestation_timeout');
});

test('claim request is rejected when its conservative sealed-response estimate exceeds budget', () => {
  const directory = mkdtempSync(join(tmpdir(), 'scan-lifecycle-budget-'));
  const jobs = createFixture({
    directory,
    now: () => new Date(currentIso),
    maxClaimBytes: 20_000_000,
    maximumEvidenceBytes: 10_000_000
  });
  jobs.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  assert.equal(jobs.maximumClaimJobs, 1);
  const oversized = signedBody({ limit: 2 }, 'nonce-0000000000001101');
  assert.throws(() => jobs.claimSigned(oversized.bytes, oversized.headers), ExternalScanClaimBudgetError);
  const allowed = signedBody({ limit: 1 }, 'nonce-0000000000001102');
  assert.equal(jobs.claimSigned(allowed.bytes, allowed.headers).jobs.length, 1);
});

test('explicit primaryPublicKeyId becomes the delivery key regardless of JSON key order', () => {
  const normalized = normaliseProviderDeliveryKeys({
    'managed-av': {
      keys: { h1: providerSecret.toString('base64') },
      primaryPublicKeyId: 'old',
      publicKeys: { old: firstRsa.publicKey, current: secondRsa.publicKey }
    }
  });
  assert.deepEqual(Object.keys(normalized['managed-av'].publicKeys), ['current', 'old']);
  const directory = mkdtempSync(join(tmpdir(), 'scan-lifecycle-primary-'));
  const outbox = createExternalScanJobOutbox({
    mode: 'pull', required: true, directory,
    evidenceKeys: { k1: evidenceKey }, evidencePrimaryKeyId: 'k1', providers: normalized,
    completedRetention: 100, deadLetterRetention: 100, now: () => new Date(currentIso)
  });
  const queued = outbox.queue(contentRecord(), 'managed-av', { actor: 'audit.manager' });
  assert.equal(queued.job.deliveryKeyId, 'old');
});

test('primaryPublicKeyId must reference an existing RSA public key', () => {
  assert.throws(() => normaliseProviderDeliveryKeys({
    'managed-av': {
      keys: { h1: providerSecret.toString('base64') },
      primaryPublicKeyId: 'missing',
      publicKeys: { current: secondRsa.publicKey }
    }
  }), /primaryPublicKeyId is not present/);
});
