import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decryptEvidenceJson,
  encryptEvidenceJson,
  parseEvidenceKeyring,
  sha256
} from '../src/evidence/evidenceCrypto.js';
import {
  EvidenceNotaryRequestAuthenticationError,
  canonicalEvidenceNotaryRequest,
  createEvidenceTimeAttestationRequestOutbox
} from '../src/evidence/evidenceTimeAttestationRequestOutbox.js';

const tenantId = 'tenant-notary-request';
const archiveId = `ARC-${'1'.repeat(32)}`;
const challenge = {
  tenantId,
  archiveId,
  receiptSha256: '2'.repeat(64),
  objectEnvelopeSha256: '3'.repeat(64),
  archivedAt: '2026-07-30T00:00:00.000Z',
  retentionUntil: '2033-07-30T00:00:00.000Z'
};
const encryptionKey = Buffer.alloc(32, 61).toString('base64');

function authority() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function fixture(options = {}) {
  const first = authority();
  const second = authority();
  let clock = new Date('2026-07-30T00:05:00.000Z');
  const directory = mkdtempSync(join(tmpdir(), 'notary-request-outbox-'));
  const providers = {
    'authority-one': { keys: { k1: { algorithm: 'ed25519', publicKeyPem: first.publicKey } } },
    'authority-two': { keys: { k1: { algorithm: 'ed25519', publicKeyPem: second.publicKey } } }
  };
  const outbox = createEvidenceTimeAttestationRequestOutbox({
    mode: 'pull',
    required: true,
    directory,
    encryptionKeys: { request: encryptionKey },
    encryptionPrimaryKeyId: 'request',
    providers,
    jobTtlMinutes: options.jobTtlMinutes ?? 60,
    claimLeaseMs: options.claimLeaseMs ?? 10_000,
    maxAttempts: options.maxAttempts ?? 2,
    completedRetention: 100,
    deadLetterRetention: 10,
    eventRetention: 100,
    clockSkewSeconds: 300,
    now: () => new Date(clock)
  });
  return {
    outbox,
    directory,
    first,
    second,
    now: () => new Date(clock),
    advance(milliseconds) { clock = new Date(clock.getTime() + milliseconds); }
  };
}

function signed(privateKey, input) {
  return {
    ...input,
    signature: sign(null, Buffer.from(canonicalEvidenceNotaryRequest(input)), privateKey).toString('base64')
  };
}

function claimRequest(privateKey, timestamp, nonce = 'authority-claim-nonce-0001', limit = 1) {
  return signed(privateKey, {
    action: 'claim', providerId: 'authority-one', keyId: 'k1', timestamp, nonce, limit
  });
}

function ackRequest(privateKey, timestamp, jobId, claimToken, nonce = 'authority-ack-nonce-00001') {
  return signed(privateKey, {
    action: 'acknowledge', providerId: 'authority-one', keyId: 'k1', timestamp,
    nonce, jobId, claimToken
  });
}

function failRequest(privateKey, timestamp, jobId, claimToken, retryable, nonce = 'authority-fail-nonce-0001') {
  return signed(privateKey, {
    action: 'fail', providerId: 'authority-one', keyId: 'k1', timestamp,
    nonce, jobId, claimToken, retryable, reasonCode: 'authority_unavailable'
  });
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

test('authority claims an encrypted provider-partitioned challenge without evidence bytes', () => {
  const { outbox, directory, first, now } = fixture();
  const queued = outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Independent time authority request'
  });
  assert.equal(queued.queued, true);
  const claim = outbox.claimSigned(claimRequest(first.privateKey, now().toISOString()));
  assert.equal(claim.jobs.length, 1);
  assert.deepEqual(claim.jobs[0].challenge, challenge);
  const raw = allFiles(directory).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.equal(raw.includes(tenantId), false);
  assert.equal(raw.includes(archiveId), false);
  assert.equal(outbox.health().plaintextEvidenceQueued, false);
  assert.equal(outbox.health().evidenceBytesQueued, false);
  assert.equal(outbox.health().arbitraryOutboundUrls, false);
});

test('signed request replay is rejected before another claim can be created', () => {
  const { outbox, first, now } = fixture();
  outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Independent time authority request'
  });
  const request = claimRequest(first.privateKey, now().toISOString());
  outbox.claimSigned(request);
  assert.throws(() => outbox.claimSigned(request), EvidenceNotaryRequestAuthenticationError);
});

test('matching attestation completes its deterministic request after acknowledgement', () => {
  const { outbox, first, now } = fixture();
  const queued = outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Independent time authority request'
  });
  const claimed = outbox.claimSigned(claimRequest(first.privateKey, now().toISOString())).jobs[0];
  const delivered = outbox.acknowledgeSigned(
    claimed.jobId,
    ackRequest(first.privateKey, now().toISOString(), claimed.jobId, claimed.claimToken)
  );
  assert.equal(delivered.state, 'delivered');
  const completion = outbox.completeFromAttestation({
    ...challenge,
    providerId: 'authority-one',
    timestamp: now().toISOString(),
    policyId: 'qualified-time-policy-v1'
  }, { attestationId: `NTA-${'4'.repeat(32)}`, policyId: 'qualified-time-policy-v1', timestamp: now().toISOString() });
  assert.equal(completion.matched, true);
  assert.equal(completion.job.state, 'completed');
  assert.equal(completion.job.jobId, queued.job.jobId);
  assert.equal(outbox.completeFromAttestation({ ...challenge, providerId: 'authority-one', timestamp: now().toISOString() }).duplicate, true);
});

test('expired claims recover and terminal failures can be requeued', () => {
  const { outbox, first, now, advance } = fixture({ claimLeaseMs: 1000, maxAttempts: 2 });
  const queued = outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Independent time authority request'
  });
  outbox.claimSigned(claimRequest(first.privateKey, now().toISOString()));
  advance(1500);
  assert.equal(outbox.list(tenantId, { archiveId })[0].state, 'pending');
  const secondClaim = outbox.claimSigned(claimRequest(
    first.privateKey,
    now().toISOString(),
    'authority-claim-nonce-0002'
  )).jobs[0];
  const failed = outbox.failSigned(
    secondClaim.jobId,
    failRequest(first.privateKey, now().toISOString(), secondClaim.jobId, secondClaim.claimToken, false)
  );
  assert.equal(failed.state, 'dead-letter');
  const requeued = outbox.requeue(tenantId, queued.job.jobId, {
    actor: 'manager.two', purpose: 'Approved retry after authority recovery'
  });
  assert.equal(requeued.job.state, 'pending');
  assert.equal(requeued.job.attempts, 0);
});

test('provider queues are isolated and cross-provider signatures cannot claim work', () => {
  const { outbox, first, second, now } = fixture();
  outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Authority one request'
  });
  outbox.queue(challenge, 'authority-two', {
    actor: 'manager.one', purpose: 'Authority two request'
  });
  const secondClaim = signed(second.privateKey, {
    action: 'claim', providerId: 'authority-two', keyId: 'k1', timestamp: now().toISOString(),
    nonce: 'authority-two-claim-0001', limit: 10
  });
  const claimed = outbox.claimSigned(secondClaim);
  assert.equal(claimed.jobs.length, 1);
  assert.equal(claimed.jobs[0].challenge.archiveId, archiveId);
  const wrong = claimRequest(second.privateKey, now().toISOString(), 'wrong-provider-signature-1');
  assert.throws(() => outbox.claimSigned(wrong), EvidenceNotaryRequestAuthenticationError);
});

test('transition chain tampering fails closed', () => {
  const { outbox, directory } = fixture();
  outbox.queue(challenge, 'authority-one', {
    actor: 'manager.one', purpose: 'Independent time authority request'
  });
  const providerDirectory = join(directory, sha256('authority-one'));
  const path = join(providerDirectory, 'notary-requests.evidence');
  const keyring = parseEvidenceKeyring({ request: encryptionKey }, 'request');
  const aad = 'basitclaw:evidence-notary-requests:authority-one';
  const envelope = JSON.parse(readFileSync(path, 'utf8'));
  const index = decryptEvidenceJson(envelope, keyring, aad);
  index.events[0].hash = 'f'.repeat(64);
  writeFileSync(path, `${JSON.stringify(encryptEvidenceJson(index, keyring, aad))}\n`);
  assert.throws(() => outbox.verifyTenant(tenantId), /transition chain/i);
});
