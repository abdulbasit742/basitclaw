import test from 'node:test';
import assert from 'node:assert/strict';
import { operationalProofRegistry } from '../src/evidence/evidenceVerificationBundleServer.js';

const archiveId = `ARC-${'a'.repeat(32)}`;

test('portable proof uses operational quorum after revocation governance', () => {
  const registry = operationalProofRegistry({
    evidenceTimeAttestationGovernanceStore: { requiredForDisposition: true },
    verifyEvidenceTimeAttestations() {
      return {
        valid: true,
        quorumSatisfied: true,
        distinctProviders: 2,
        providerIds: ['authority-a', 'authority-b'],
        operationalQuorumSatisfied: false,
        acceptableDistinctProviders: 1,
        acceptableProviderIds: ['authority-b']
      };
    },
    effectiveArchiveVerification() {
      return {
        attestationDecisions: [
          { attestationId: 'NTA-revoked', governance: { operationallyAcceptable: false, status: 'revoked' } },
          { attestationId: 'NTA-accepted', governance: { operationallyAcceptable: true, status: 'acceptable' } }
        ]
      };
    },
    evidenceTimeAttestations() { throw new Error('governance evaluation should be used'); }
  });

  const verification = registry.verifyEvidenceTimeAttestations('tenant-a', archiveId);
  assert.equal(verification.quorumSatisfied, false);
  assert.equal(verification.distinctProviders, 1);
  assert.deepEqual(verification.providerIds, ['authority-b']);
  assert.equal(verification.governanceRequiredForDisposition, true);

  const records = registry.evidenceTimeAttestations('tenant-a', archiveId, { limit: 10 });
  assert.deepEqual(records.map((record) => record.attestationId), ['NTA-accepted']);
});

test('portable proof preserves cryptographic posture when governance fields are absent', () => {
  const registry = operationalProofRegistry({
    evidenceTimeAttestationGovernanceStore: { requiredForDisposition: false },
    verifyEvidenceTimeAttestations() {
      return { valid: true, quorumSatisfied: true, distinctProviders: 2, providerIds: ['a', 'b'] };
    },
    evidenceTimeAttestations() { return [{ attestationId: 'NTA-legacy' }]; }
  });
  const verification = registry.verifyEvidenceTimeAttestations('tenant-a', archiveId);
  assert.equal(verification.quorumSatisfied, true);
  assert.equal(verification.distinctProviders, 2);
  assert.deepEqual(registry.evidenceTimeAttestations('tenant-a', archiveId), [{ attestationId: 'NTA-legacy' }]);
});
