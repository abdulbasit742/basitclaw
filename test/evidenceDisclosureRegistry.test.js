import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EvidenceConflictError } from '../src/evidence/evidenceRegistry.js';
import { createEvidenceDisclosureBundleStore } from '../src/evidence/evidenceDisclosureBundleStore.js';
import { createEvidenceDisclosureRegistry } from '../src/evidence/evidenceDisclosureRegistry.js';
import { verifyAndDecryptDisclosurePackage } from '../src/evidence/evidenceDisclosureVerifier.js';

const tenantId = 'tenant-registry-disclosure';
const evidenceId = `EVD-${'e'.repeat(32)}`;
const archiveId = `ARC-${'f'.repeat(32)}`;
const contentSha256 = 'a'.repeat(64);
const recipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
const signing = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function disclosureStore() {
  return createEvidenceDisclosureBundleStore({
    mode: 'shared-file',
    directory: mkdtempSync(join(tmpdir(), 'disclosure-registry-')),
    indexKeys: { index: Buffer.alloc(32, 91).toString('base64') },
    indexPrimaryKeyId: 'index',
    recipients: { auditor: { primaryKeyId: 'rsa-1', publicKeys: { 'rsa-1': recipient.publicKey } } },
    signingKeys: { enterprise: { privateKey: signing.privateKey } },
    signingPrimaryKeyId: 'enterprise',
    now: () => new Date('2026-07-30T03:00:00.000Z')
  });
}

function baseRegistry({ preservation = true, operationalQuorum = true } = {}) {
  const item = {
    evidenceId,
    filename: 'sensitive-payroll.csv',
    mediaType: 'text/csv',
    status: 'active',
    currentVersion: 1,
    retentionUntil: '2033-07-30T00:00:00.000Z',
    legalHold: { active: false, matterId: 'must-not-leak' },
    versions: [{ version: 1, filename: 'sensitive-payroll.csv', mediaType: 'text/csv', sizeBytes: 123, sha256: contentSha256, createdAt: '2026-07-01T00:00:00.000Z' }]
  };
  const receipt = {
    receiptId: 'PRR-test', archiveId, evidenceId, evidenceVersion: 1,
    contentSha256, sizeBytes: 123, objectEnvelopeSha256: 'b'.repeat(64),
    retentionUntil: item.retentionUntil, archivedAt: '2026-07-02T00:00:00.000Z',
    immutabilityMode: 'backend-confirmed-write-once', signingKeyId: 'receipt-1', signature: 'c2lnbmF0dXJl'
  };
  const decisions = [
    {
      attestationId: 'NTA-1', archiveId, providerId: 'tsa-a', keyId: 'a1',
      receiptSha256: 'c'.repeat(64), objectEnvelopeSha256: receipt.objectEnvelopeSha256,
      timestamp: '2026-07-02T00:01:00.000Z', policyId: 'policy-a', nonce: 'nonce-a',
      sequence: 1, receivedAt: '2026-07-02T00:01:10.000Z', previousHash: null, hash: 'd'.repeat(64),
      governance: { cryptographicallyValid: true, operationallyAcceptable: operationalQuorum, status: operationalQuorum ? 'acceptable' : 'revoked', reasons: operationalQuorum ? [] : [{ reasonCode: 'authority_compromise', reason: 'must-not-leak' }] }
    },
    {
      attestationId: 'NTA-2', archiveId, providerId: 'tsa-b', keyId: 'b1',
      receiptSha256: 'c'.repeat(64), objectEnvelopeSha256: receipt.objectEnvelopeSha256,
      timestamp: '2026-07-02T00:02:00.000Z', policyId: 'policy-b', nonce: 'nonce-b',
      sequence: 2, receivedAt: '2026-07-02T00:02:10.000Z', previousHash: 'd'.repeat(64), hash: 'e'.repeat(64),
      governance: { cryptographicallyValid: true, operationallyAcceptable: true, status: 'acceptable', reasons: [] }
    }
  ];
  return {
    evidenceTimeAttestationEnabled: true,
    evidenceTimeAttestationGovernanceEnabled: true,
    evidencePreservationEnabled: true,
    evidencePreservationStore: { directory: '/tmp/fake', verifiedForVersion() { return preservation ? receipt : null; } },
    get(requestTenant, requestEvidenceId) { assert.equal(requestTenant, tenantId); assert.equal(requestEvidenceId, evidenceId); return structuredClone(item); },
    list() { return [structuredClone(item)]; },
    verify() { return { valid: true, evidenceId, checkedVersions: 1, chain: { valid: true }, preservation: { valid: true }, timeAttestations: { valid: true }, timeAttestationGovernance: { valid: true } }; },
    screeningReport() {
      return { version: 1, status: 'clean', screenedAt: '2026-07-01T01:00:00.000Z', engineVersion: '1.0', findings: [{ code: 'SAFE', severity: 'info', category: 'admission', matchedValue: 'must-not-leak' }] };
    },
    externalScanAttestations() {
      return [{ attestationId: 'ATT-1', providerId: 'managed-av', verdict: 'clean', scannedAt: '2026-07-01T02:00:00.000Z', receivedAt: '2026-07-01T02:01:00.000Z', contentSha256, findings: [{ code: 'NO_THREAT', matchedValue: 'must-not-leak' }] }];
    },
    verifyEvidenceTimeAttestations() { return this.effectiveArchiveVerification(); },
    effectiveArchiveVerification() {
      return {
        valid: true, cryptographicallyValid: true, archiveId, attestationCount: 2, distinctProviders: 2,
        minimumProviders: 2, quorumSatisfied: true, governanceEnabled: true,
        governanceEvaluatedAt: '2026-07-30T03:00:00.000Z', governanceEventsConsidered: operationalQuorum ? 0 : 1,
        operationalQuorumSatisfied: operationalQuorum,
        acceptableAttestations: operationalQuorum ? 2 : 1,
        acceptableDistinctProviders: operationalQuorum ? 2 : 1,
        acceptableProviderIds: operationalQuorum ? ['tsa-a', 'tsa-b'] : ['tsa-b'],
        rejectedAttestations: operationalQuorum ? 0 : 1,
        attestationDecisions: decisions
      };
    },
    health() { return { status: 'ready', required: true }; },
    tenantStatus() { return { status: 'ready' }; }
  };
}

function request(overrides = {}) {
  return {
    recipientId: 'auditor', idempotencyKey: 'annual-audit-001', purpose: 'Independent workforce assurance review',
    confirmation: `CREATE DISCLOSURE ${evidenceId}`, ...overrides
  };
}

test('registry exports only whitelisted proof fields after preservation and operational notary quorum checks', () => {
  const store = disclosureStore();
  const registry = createEvidenceDisclosureRegistry({ registry: baseRegistry(), disclosures: store });
  const created = registry.createDisclosureBundle(tenantId, evidenceId, request(), { actor: 'manager.one' });
  const opened = verifyAndDecryptDisclosurePackage(registry.disclosurePackage(tenantId, created.bundle.bundleId), {
    recipientPrivateKey: recipient.privateKey,
    enterprisePublicKeys: { enterprise: signing.publicKey },
    now: () => new Date('2026-07-31T00:00:00.000Z')
  });
  const text = JSON.stringify(opened.payload);
  assert.equal(opened.payload.evidence.versions[0].filename, null);
  assert.equal(text.includes('must-not-leak'), false);
  assert.equal(text.includes('matchedValue'), false);
  assert.equal(text.includes('contentBase64'), false);
  assert.equal(opened.payload.evidence.versions[0].preservationReceipt.archiveId, archiveId);
  assert.equal(opened.payload.evidence.versions[0].timeAttestationVerification.operationalQuorumSatisfied, true);
  assert.equal(opened.payload.integrity.notaryGovernanceEvaluated, true);
});

test('explicit filename disclosure is represented in the signed encrypted payload', () => {
  const store = disclosureStore();
  const registry = createEvidenceDisclosureRegistry({ registry: baseRegistry(), disclosures: store });
  const created = registry.createDisclosureBundle(tenantId, evidenceId, request({ includeFilenames: true }), { actor: 'manager.one' });
  const opened = verifyAndDecryptDisclosurePackage(registry.disclosurePackage(tenantId, created.bundle.bundleId), {
    recipientPrivateKey: recipient.privateKey, enterprisePublicKeys: { enterprise: signing.publicKey }, now: () => new Date('2026-07-31T00:00:00.000Z')
  });
  assert.equal(opened.payload.evidence.filenameIncluded, true);
  assert.equal(opened.payload.evidence.versions[0].filename, 'sensitive-payroll.csv');
});

test('missing preservation or operational notary quorum blocks disclosure creation', () => {
  const withoutPreservation = createEvidenceDisclosureRegistry({ registry: baseRegistry({ preservation: false }), disclosures: disclosureStore() });
  assert.throws(() => withoutPreservation.createDisclosureBundle(tenantId, evidenceId, request(), { actor: 'manager.one' }), EvidenceConflictError);
  const withoutOperationalQuorum = createEvidenceDisclosureRegistry({ registry: baseRegistry({ operationalQuorum: false }), disclosures: disclosureStore() });
  assert.throws(() => withoutOperationalQuorum.createDisclosureBundle(tenantId, evidenceId, request(), { actor: 'manager.one' }), EvidenceConflictError);
});

test('confirmation and version selection are strict', () => {
  const registry = createEvidenceDisclosureRegistry({ registry: baseRegistry(), disclosures: disclosureStore() });
  assert.throws(() => registry.createDisclosureBundle(tenantId, evidenceId, request({ confirmation: 'CREATE DISCLOSURE wrong' }), { actor: 'manager.one' }), /confirmation/);
  assert.throws(() => registry.createDisclosureBundle(tenantId, evidenceId, request({ versions: [2] }), { actor: 'manager.one' }), /unavailable evidence version/);
});
