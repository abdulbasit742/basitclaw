import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  EvidenceVerificationBundleIntegrityError,
  createEvidenceVerificationBundleService,
  verifyPortableEvidenceBundle
} from '../src/evidence/evidenceVerificationBundle.js';

const evidenceId = `EVD-${'a'.repeat(32)}`;
const archiveId = `ARC-${'b'.repeat(32)}`;
const contentSha256 = 'c'.repeat(64);
const objectEnvelopeSha256 = 'd'.repeat(64);
const rsa = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { format: 'pem', type: 'spki' },
  privateKeyEncoding: { format: 'pem', type: 'pkcs8' }
});
const ed = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { format: 'pem', type: 'spki' },
  privateKeyEncoding: { format: 'pem', type: 'pkcs8' }
});

function registryFixture({ quorum = true } = {}) {
  const receipt = {
    receiptId: `PRR-${'e'.repeat(32)}`,
    archiveId,
    evidenceId,
    evidenceVersion: 1,
    contentSha256,
    sizeBytes: 128,
    objectEnvelopeSha256,
    retentionUntil: '2035-01-01T00:00:00.000Z',
    legalHoldActive: false,
    archivedAt: '2026-07-30T00:00:00.000Z',
    immutabilityMode: 'backend-confirmed-write-once',
    signingKeyId: 'preservation-q3',
    signature: Buffer.alloc(32, 7).toString('base64')
  };
  return {
    get() {
      return {
        evidenceId,
        filename: 'payroll.csv',
        mediaType: 'text/csv',
        status: 'active',
        currentVersion: 1,
        retentionUntil: receipt.retentionUntil,
        createdAt: '2026-07-29T00:00:00.000Z',
        updatedAt: '2026-07-30T00:00:00.000Z',
        legalHold: { active: false },
        versions: [{
          version: 1,
          filename: 'payroll.csv',
          mediaType: 'text/csv',
          sha256: contentSha256,
          sizeBytes: 128,
          screeningStatus: 'clean'
        }]
      };
    },
    evidencePreservationStore: {
      verifiedForVersion() { return receipt; }
    },
    verifyEvidencePreservation() {
      return { valid: true, archiveId, receipt };
    },
    verifyEvidenceTimeAttestations() {
      return {
        valid: true,
        archiveId,
        attestationCount: quorum ? 2 : 1,
        distinctProviders: quorum ? 2 : 1,
        minimumProviders: 2,
        quorumSatisfied: quorum,
        providerIds: quorum ? ['notary-a', 'notary-b'] : ['notary-a']
      };
    },
    evidenceTimeAttestations() {
      return [{
        attestationId: `NTA-${'f'.repeat(32)}`,
        archiveId,
        providerId: 'notary-a',
        keyId: 'key-1',
        receiptSha256: '1'.repeat(64),
        objectEnvelopeSha256,
        timestamp: '2026-07-30T00:05:00.000Z',
        policyId: 'policy-1',
        sequence: 1,
        receivedAt: '2026-07-30T00:05:05.000Z',
        previousHash: null,
        hash: '2'.repeat(64)
      }];
    }
  };
}

function serviceFixture(options = {}) {
  return createEvidenceVerificationBundleService({
    registry: registryFixture(options),
    mode: 'signed',
    signingKeys: {
      ed1: { algorithm: 'ed25519', privateKeyPem: ed.privateKey },
      rsa1: { algorithm: 'rsa-pss-sha256', privateKeyPem: rsa.privateKey }
    },
    primarySigningKeyId: options.primarySigningKeyId ?? 'ed1',
    maximumAgeDays: 30,
    requireTimeQuorum: true,
    now: () => new Date('2026-07-30T01:00:00.000Z')
  });
}

function request() {
  return {
    version: 1,
    profile: 'audit',
    recipientRef: 'external-auditor-2026',
    purpose: 'Independent year-end assurance review',
    confirmation: `EXPORT PROOF ${evidenceId} V1`
  };
}

test('creates an Ed25519-signed portable proof with no raw evidence bytes', () => {
  const service = serviceFixture();
  const result = service.create('tenant-a', evidenceId, request(), { actor: 'manager.one' });
  assert.equal(result.created, true);
  assert.equal(result.bundle.signature.algorithm, 'ed25519');
  assert.equal(result.bundle.proof.timeAttestations.quorumSatisfied, true);
  assert.equal(JSON.stringify(result.bundle).includes('contentBase64'), false);
  assert.equal(JSON.stringify(result.bundle).includes('rawContent'), false);
  const verified = service.verify(result.bundle, { now: () => new Date('2026-07-31T00:00:00.000Z') });
  assert.equal(verified.valid, true);
  assert.equal(verified.bundleId, result.bundle.bundleId);
});

test('RSA-PSS bundles verify with an exported trusted public key', () => {
  const service = serviceFixture({ primarySigningKeyId: 'rsa1' });
  const result = service.create('tenant-a', evidenceId, request(), { actor: 'manager.one' });
  const verified = verifyPortableEvidenceBundle(result.bundle, service.publicSigningKeys, {
    now: () => new Date('2026-07-31T00:00:00.000Z')
  });
  assert.equal(verified.valid, true);
  assert.equal(verified.signingAlgorithm, 'rsa-pss-sha256');
});

test('tampering with proof or signature fails closed', () => {
  const service = serviceFixture();
  const result = service.create('tenant-a', evidenceId, request(), { actor: 'manager.one' });
  const proofTamper = structuredClone(result.bundle);
  proofTamper.proof.evidence.sizeBytes += 1;
  assert.throws(() => service.verify(proofTamper), EvidenceVerificationBundleIntegrityError);
  const signatureTamper = structuredClone(result.bundle);
  signatureTamper.signature.value = signatureTamper.signature.value.replace(/^./, 'A');
  assert.throws(() => service.verify(signatureTamper), EvidenceVerificationBundleIntegrityError);
});

test('proof export fails without independent time-attestation quorum', () => {
  const service = serviceFixture({ quorum: false });
  assert.throws(
    () => service.create('tenant-a', evidenceId, request(), { actor: 'manager.one' }),
    /time-attestation quorum/
  );
});

test('exact confirmation and safe recipient purpose are required', () => {
  const service = serviceFixture();
  assert.throws(
    () => service.create('tenant-a', evidenceId, { ...request(), confirmation: 'EXPORT' }, { actor: 'manager.one' }),
    /confirmation must be exactly/
  );
  assert.throws(
    () => service.create('tenant-a', evidenceId, { ...request(), recipientRef: 'bad\nrecipient' }, { actor: 'manager.one' }),
    /safe characters/
  );
});
