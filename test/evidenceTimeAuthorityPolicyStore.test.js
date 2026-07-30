import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  EvidenceTimeAuthorityPolicyError,
  createEvidenceTimeAuthorityPolicyStore
} from '../src/evidence/evidenceTimeAuthorityPolicyStore.js';
import {
  canonicalTimeAttestation,
  createEvidenceTimeAttestationStore
} from '../src/evidence/evidenceTimeAttestationStore.js';
import { createEvidenceTimeAttestationGovernanceRegistry } from '../src/evidence/evidenceTimeAttestationGovernanceRegistry.js';
import { createEvidenceTimeAttestationGovernanceStore } from '../src/evidence/evidenceTimeAttestationGovernanceStore.js';

const tenantId = 'tenant-authority-policy';
const archiveId = `ARC-${'a'.repeat(32)}`;
const challenge = {
  tenantId,
  archiveId,
  receiptSha256: 'b'.repeat(64),
  objectEnvelopeSha256: 'c'.repeat(64),
  archivedAt: '2026-07-30T00:00:00.000Z',
  retentionUntil: '2033-07-30T00:00:00.000Z'
};
const nowValue = '2026-07-30T00:10:00.000Z';
const encryptionKey = Buffer.alloc(32, 119).toString('base64');

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

function providers(first, second = null, overrides = {}) {
  const output = {
    'authority-one': {
      keys: {
        k1: {
          algorithm: 'ed25519',
          publicKeyPem: first.publicKey,
          validFrom: '2026-07-29T00:00:00.000Z',
          validUntil: '2027-07-30T00:00:00.000Z',
          allowedPolicyIds: ['qualified-policy-v1'],
          ...overrides.first
        }
      }
    }
  };
  if (second) {
    output['authority-two'] = {
      keys: {
        k2: {
          algorithm: 'ed25519',
          publicKeyPem: second.publicKey,
          validFrom: '2026-07-29T00:00:00.000Z',
          validUntil: '2027-07-30T00:00:00.000Z',
          allowedPolicyIds: ['qualified-policy-v1'],
          ...overrides.second
        }
      }
    };
  }
  return output;
}

function submission(providerId, keyId, privateKey, timestamp, nonce, policyId = 'qualified-policy-v1') {
  const input = {
    tenantId,
    archiveId,
    providerId,
    keyId,
    receiptSha256: challenge.receiptSha256,
    objectEnvelopeSha256: challenge.objectEnvelopeSha256,
    timestamp,
    policyId,
    nonce
  };
  return {
    ...input,
    signature: sign(null, Buffer.from(canonicalTimeAttestation(input)), privateKey).toString('base64')
  };
}

function fixture({ minimumProviders = 1, requiredForDisposition = false, policyProviders } = {}) {
  const first = keyPair();
  const second = keyPair();
  const baseProviders = providers(first, second);
  const base = createEvidenceTimeAttestationStore({
    mode: 'shared-file', requiredForDisposition, minimumProviders,
    directory: mkdtempSync(join(tmpdir(), 'authority-policy-')),
    encryptionKeys: { n1: encryptionKey }, encryptionPrimaryKeyId: 'n1',
    providers: baseProviders, resolveChallenge: () => challenge,
    now: () => new Date(nowValue), maxRecords: 100
  });
  const policy = createEvidenceTimeAuthorityPolicyStore({
    store: base,
    providers: policyProviders?.(first, second) ?? baseProviders,
    expiryWarningDays: 45,
    now: () => new Date(nowValue)
  });
  return { base, policy, first, second };
}

test('accepts only authority timestamps and policy IDs inside the configured key policy', () => {
  const { policy, first } = fixture();
  const accepted = policy.record(submission(
    'authority-one', 'k1', first.privateKey,
    '2026-07-30T00:05:00.000Z', 'policy-valid-nonce-0001'
  ));
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.attestation.authorityPolicy.trusted, true);
  const verified = policy.verifyArchive(tenantId, archiveId);
  assert.equal(verified.quorumSatisfied, true);
  assert.equal(verified.policyCompliantAttestations, 1);
});

test('rejects not-yet-valid, expired and unapproved-policy submissions after signature authentication', () => {
  const { policy, first } = fixture({
    policyProviders: (one, two) => providers(one, two, {
      first: {
        validFrom: '2026-07-30T00:04:00.000Z',
        validUntil: '2026-07-30T00:06:00.000Z',
        allowedPolicyIds: ['approved-policy']
      }
    })
  });
  assert.throws(
    () => policy.record(submission('authority-one', 'k1', first.privateKey, '2026-07-30T00:03:00.000Z', 'policy-early-nonce-0001', 'approved-policy')),
    (error) => error instanceof EvidenceTimeAuthorityPolicyError && error.details.reason === 'key_not_yet_valid'
  );
  assert.throws(
    () => policy.record(submission('authority-one', 'k1', first.privateKey, '2026-07-30T00:07:00.000Z', 'policy-expired-nonce-01', 'approved-policy')),
    (error) => error instanceof EvidenceTimeAuthorityPolicyError && error.details.reason === 'key_expired_at_attestation'
  );
  assert.throws(
    () => policy.record(submission('authority-one', 'k1', first.privateKey, '2026-07-30T00:05:00.000Z', 'policy-denied-nonce-001', 'unapproved-policy')),
    (error) => error instanceof EvidenceTimeAuthorityPolicyError && error.details.reason === 'policy_not_allowed'
  );
});

test('historical cryptographic quorum is recalculated from policy-compliant distinct providers', () => {
  const { base, first, second } = fixture({ minimumProviders: 2 });
  base.record(submission('authority-one', 'k1', first.privateKey, '2026-07-30T00:05:00.000Z', 'policy-quorum-one-00001'));
  base.record(submission('authority-two', 'k2', second.privateKey, '2026-07-30T00:05:30.000Z', 'policy-quorum-two-00001'));
  const evaluated = createEvidenceTimeAuthorityPolicyStore({
    store: base,
    providers: providers(first, second, {
      second: { validUntil: '2026-07-30T00:05:00.000Z' }
    }),
    now: () => new Date(nowValue)
  });
  const verified = evaluated.verifyArchive(tenantId, archiveId);
  assert.equal(verified.cryptographicQuorumSatisfied, true);
  assert.equal(verified.policyCompliantDistinctProviders, 1);
  assert.equal(verified.quorumSatisfied, false);
  assert.equal(verified.policyRejectionReasons.key_expired_at_attestation, 1);
});

test('required policy health fails closed when active authority providers cannot satisfy quorum', () => {
  const { base, first, second } = fixture({ minimumProviders: 2, requiredForDisposition: true });
  const evaluated = createEvidenceTimeAuthorityPolicyStore({
    store: base,
    providers: providers(first, second, {
      second: { validFrom: '2026-08-30T00:00:00.000Z' }
    }),
    now: () => new Date(nowValue)
  });
  const health = evaluated.health();
  assert.equal(health.status, 'unavailable');
  assert.equal(health.authorityPolicy.activeProviders, 1);
  assert.equal(health.authorityPolicy.quorumAvailable, false);
});

test('optional policy-provider shortfall surfaces attention instead of false readiness', () => {
  const first = keyPair();
  const mock = {
    enabled: true, requiredForDisposition: false, minimumProviders: 1,
    record() {}, list() { return []; },
    verifyArchives() { return { valid: true, results: new Map() }; },
    verifyTenant() { return { valid: true }; },
    tenantStatus() { return { status: 'ready' }; },
    health() { return { status: 'ready' }; }
  };
  const evaluated = createEvidenceTimeAuthorityPolicyStore({
    store: mock,
    providers: providers(first, null, { first: { validUntil: '2026-07-29T12:00:00.000Z' } }),
    now: () => new Date(nowValue)
  });
  assert.equal(evaluated.health().status, 'attention');
  assert.equal(evaluated.tenantStatus(tenantId).status, 'attention');
});

test('operational governance cannot restore an attestation rejected by authority key policy', () => {
  const attestation = {
    attestationId: `NTA-${'d'.repeat(32)}`,
    archiveId,
    providerId: 'authority-one',
    keyId: 'k1',
    timestamp: '2026-07-30T00:05:00.000Z',
    authorityPolicy: { trusted: false, reason: 'policy_not_allowed' }
  };
  const baseRegistry = {
    evidenceTimeAttestationStore: { minimumProviders: 1, authorityPolicyEnabled: true, list() { return [attestation]; } },
    evidencePreservationStore: { verifiedForVersion() { return null; } },
    evidenceTimeAttestationEnabled: true,
    verifyEvidenceTimeAttestations() {
      return { valid: true, archiveId, minimumProviders: 1, quorumSatisfied: false };
    },
    evidenceTimeAttestations() { return [attestation]; },
    recordTimeAttestation() { return { accepted: true, attestation }; },
    dispose() {}, verify() { return { valid: true }; },
    health() { return { status: 'ready' }; }, tenantStatus() { return { status: 'ready' }; },
    evidenceTimeAttestationStatus() { return { status: 'ready' }; },
    get() { return { evidenceId: `EVD-${'e'.repeat(32)}`, versions: [] }; },
    list() { return []; }
  };
  const governance = createEvidenceTimeAttestationGovernanceStore({ mode: 'disabled' });
  const registry = createEvidenceTimeAttestationGovernanceRegistry({ registry: baseRegistry, governance });
  const verified = registry.effectiveArchiveVerification(tenantId, archiveId);
  assert.equal(verified.governanceEnabled, false);
  assert.equal(verified.policyRejectedAttestations, 1);
  assert.equal(verified.operationalQuorumSatisfied, false);
  assert.equal(verified.acceptableDistinctProviders, 0);
});
