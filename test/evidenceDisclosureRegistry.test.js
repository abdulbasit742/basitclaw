import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createEvidenceDisclosureRegistry, EvidenceDisclosureTrustError } from '../src/evidence/evidenceDisclosureRegistry.js';

const tenantId = 'tenant-registry-disclosure';
const evidenceId = `EVD-${'b'.repeat(32)}`;
const recipient = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

function baseFixture({ receipt = true, quorum = true } = {}) {
  const metadata = {
    evidenceId,
    filename: 'payroll.csv',
    mediaType: 'text/csv',
    status: 'active',
    currentVersion: 1,
    retentionUntil: '2035-01-01T00:00:00.000Z',
    legalHold: { active: false },
    versions: [{
      version: 1,
      filename: 'payroll.csv',
      mediaType: 'text/csv',
      sha256: '1'.repeat(64),
      sizeBytes: 7,
      screeningStatus: 'released'
    }]
  };
  let captured = null;
  const preservationReceipt = receipt ? {
    receiptId: 'PRR-example',
    archiveId: `ARC-${'c'.repeat(32)}`,
    evidenceId,
    evidenceVersion: 1,
    contentSha256: '1'.repeat(64),
    sizeBytes: 7,
    objectEnvelopeSha256: '2'.repeat(64),
    retentionUntil: metadata.retentionUntil,
    archivedAt: '2030-01-01T00:00:00.000Z',
    immutabilityMode: 'backend-confirmed-write-once',
    signingKeyId: 'archive-signing',
    signature: 'signed-receipt'
  } : null;
  const registry = {
    get(requestedTenant, requestedEvidence) {
      assert.equal(requestedTenant, tenantId);
      assert.equal(requestedEvidence, evidenceId);
      return metadata;
    },
    readContent() { return { content: Buffer.from('payroll'), sha256: '1'.repeat(64), sizeBytes: 7 }; },
    verifyEvidencePreservation(_tenant, archiveId) {
      return { valid: true, archiveId, receipt: preservationReceipt, object: { contentSha256: '1'.repeat(64), sizeBytes: 7, encryptionKeyId: 'archive-key' } };
    },
    verifyEvidenceTimeAttestations() {
      return { valid: true, archiveId: preservationReceipt?.archiveId, quorumSatisfied: quorum, minimumProviders: 2, distinctProviders: quorum ? 2 : 1, checkedAttestations: quorum ? 2 : 1 };
    },
    evidenceTimeAttestations() { return quorum ? [{ providerId: 'authority-one' }, { providerId: 'authority-two' }] : [{ providerId: 'authority-one' }]; },
    evidencePreservationStore: {
      verifiedForVersion() { return preservationReceipt; }
    },
    health() { return { status: 'ready' }; },
    tenantStatus() { return { status: 'ready' }; }
  };
  const disclosures = {
    enabled: true,
    create(value, context) { captured = { value, context }; return { created: true, duplicate: false, disclosure: { packageId: `DSP-${'d'.repeat(32)}`, itemCount: value.itemCount } }; },
    list() { return []; },
    metadata() { return {}; },
    download() { return {}; },
    verify() { return {}; },
    revoke() { return {}; },
    tenantStatus() { return { status: 'ready', enabled: true }; },
    health() { return { status: 'ready', enabled: true }; }
  };
  return { registry, disclosures, captured: () => captured };
}

function request(overrides = {}) {
  return {
    recipientKeyId: 'regulator-key-1',
    recipientPublicKeyPem: recipient.publicKey,
    expiresAt: '2035-06-01T00:00:00.000Z',
    maximumDownloads: 2,
    purpose: 'Regulatory disclosure for an external audit authority',
    items: [{ evidenceId, version: 1 }],
    confirmation: 'DISCLOSE 1 EVIDENCE VERSIONS TO regulator-key-1',
    ...overrides
  };
}

test('builds a disclosure payload only after preservation and notary verification', () => {
  const fixture = baseFixture();
  const registry = createEvidenceDisclosureRegistry({ registry: fixture.registry, disclosures: fixture.disclosures, requireNotaryQuorum: true });
  const result = registry.createEvidenceDisclosure(tenantId, request(), { actor: 'manager.one' });
  assert.equal(result.created, true);
  const captured = fixture.captured();
  assert.equal(captured.value.payload.evidence.length, 1);
  assert.equal(captured.value.payload.evidence[0].contentBase64, Buffer.from('payroll').toString('base64'));
  assert.equal(captured.value.payload.evidence[0].preservation.verified.valid, true);
  assert.equal(captured.value.payload.evidence[0].timeAttestations.verification.quorumSatisfied, true);
  assert.match(captured.value.payload.tenantScope, /^tenant-sha256:[a-f0-9]{64}$/);
  assert.equal(captured.context.actor, 'manager.one');
});

test('missing preservation receipt blocks disclosure', () => {
  const fixture = baseFixture({ receipt: false });
  const registry = createEvidenceDisclosureRegistry({ registry: fixture.registry, disclosures: fixture.disclosures });
  assert.throws(() => registry.createEvidenceDisclosure(tenantId, request(), { actor: 'manager.one' }), EvidenceDisclosureTrustError);
  assert.equal(fixture.captured(), null);
});

test('insufficient distinct time-authority quorum blocks disclosure by default', () => {
  const fixture = baseFixture({ quorum: false });
  const registry = createEvidenceDisclosureRegistry({ registry: fixture.registry, disclosures: fixture.disclosures, requireNotaryQuorum: true });
  assert.throws(() => registry.createEvidenceDisclosure(tenantId, request(), { actor: 'manager.one' }), EvidenceDisclosureTrustError);
  assert.equal(fixture.captured(), null);
});

test('duplicates and unsupported request fields are rejected before package creation', () => {
  const fixture = baseFixture();
  const registry = createEvidenceDisclosureRegistry({ registry: fixture.registry, disclosures: fixture.disclosures });
  assert.throws(() => registry.createEvidenceDisclosure(tenantId, request({
    items: [{ evidenceId, version: 1 }, { evidenceId, version: 1 }],
    confirmation: 'DISCLOSE 2 EVIDENCE VERSIONS TO regulator-key-1'
  }), { actor: 'manager.one' }), /unique/);
  assert.throws(() => registry.createEvidenceDisclosure(tenantId, request({ extra: true }), { actor: 'manager.one' }), /unsupported field/);
});
