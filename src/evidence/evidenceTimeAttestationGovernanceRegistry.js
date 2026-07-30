import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationRegistryFromEnvironment } from './evidenceTimeAttestationRegistry.js';
import {
  EvidenceTimeAttestationGovernanceRequiredError,
  createEvidenceTimeAttestationGovernanceStore,
  createEvidenceTimeAttestationGovernanceStoreFromEnvironment
} from './evidenceTimeAttestationGovernanceStore.js';

export function createEvidenceTimeAttestationGovernanceRegistry({
  registry,
  governance = createEvidenceTimeAttestationGovernanceStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.verifyEvidenceTimeAttestations !== 'function'
      || typeof registry.evidenceTimeAttestations !== 'function' || typeof registry.dispose !== 'function') {
    throw new TypeError('A time-attestation-aware evidence registry is required.');
  }
  if (!governance || typeof governance.record !== 'function' || typeof governance.evaluate !== 'function') {
    throw new TypeError('A time-attestation governance store is required.');
  }

  function recordTimeAttestation(input) {
    const result = registry.recordTimeAttestation(input);
    if (!governance.enabled) return result;
    const evaluation = governance.evaluate(input.tenantId, [result.attestation]);
    return {
      ...result,
      governance: publicDecision(evaluation.decisions.get(result.attestation.attestationId))
    };
  }

  function recordTimeAttestationGovernanceEvent(tenantId, input, context = {}) {
    if (!governance.enabled) throw new EvidenceConflictError('Time-attestation governance is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid time-attestation governance request is required.');
    }
    validateGovernanceTarget(tenantId, input);
    assertConfirmation(input);
    return governance.record(tenantId, input, { actor: context.actor });
  }

  function validateGovernanceTarget(tenantId, input) {
    if (input.eventType === 'attestation_revoked' || input.eventType === 'attestation_superseded') {
      registry.verifyEvidenceTimeAttestations(tenantId, input.archiveId);
      const records = registry.evidenceTimeAttestations(tenantId, input.archiveId, { limit: 5000 });
      const original = records.find((record) => record.attestationId === input.attestationId);
      if (!original) {
        throw new EvidenceValidationError('The governed time attestation does not exist for the archive.', {
          field: 'attestationId', attestationId: input.attestationId
        });
      }
      if (input.eventType === 'attestation_superseded') {
        const replacement = records.find((record) => record.attestationId === input.replacementAttestationId);
        if (!replacement) {
          throw new EvidenceValidationError('The replacement time attestation does not exist for the archive.', {
            field: 'replacementAttestationId', replacementAttestationId: input.replacementAttestationId
          });
        }
      }
    }
  }

  function assertConfirmation(input) {
    let expected;
    if (input.eventType === 'attestation_revoked') {
      expected = `REVOKE ATTESTATION ${input.attestationId}`;
    } else if (input.eventType === 'attestation_superseded') {
      expected = `SUPERSEDE ATTESTATION ${input.attestationId} WITH ${input.replacementAttestationId}`;
    } else if (input.eventType === 'provider_revoked') {
      expected = `REVOKE NOTARY PROVIDER ${input.providerId}`;
    } else if (input.eventType === 'key_revoked') {
      expected = `REVOKE NOTARY KEY ${input.providerId}/${input.keyId}`;
    } else {
      throw new EvidenceValidationError('eventType is invalid.', { field: 'eventType' });
    }
    if (input.confirmation !== expected) {
      throw new EvidenceValidationError(`confirmation must be exactly ${expected}.`, { field: 'confirmation' });
    }
  }

  function evidenceTimeAttestationGovernanceEvents(tenantId, options = {}) {
    return governance.list(tenantId, options);
  }

  function verifyEvidenceTimeAttestationGovernance(tenantId) {
    return governance.verifyTenant(tenantId);
  }

  function effectiveArchiveVerification(tenantId, archiveId, { at = undefined } = {}) {
    const cryptographic = registry.verifyEvidenceTimeAttestations(tenantId, archiveId);
    const attestations = registry.evidenceTimeAttestations(tenantId, archiveId, { limit: 5000 });
    const evaluation = governance.evaluate(tenantId, attestations, at ? { at } : {});
    const policyCompliant = attestations.filter((attestation) => attestation.authorityPolicy?.trusted !== false);
    const acceptable = policyCompliant.filter(
      (attestation) => evaluation.decisions.get(attestation.attestationId)?.operationallyAcceptable
    );
    const providerIds = [...new Set(acceptable.map((attestation) => attestation.providerId))].sort();
    const minimumProviders = registry.evidenceTimeAttestationStore.minimumProviders;
    return {
      ...cryptographic,
      cryptographicallyValid: true,
      governanceEnabled: governance.enabled,
      governanceEvaluatedAt: evaluation.evaluatedAt,
      governanceEventsConsidered: evaluation.eventsConsidered,
      authorityPolicyEnforced: Boolean(registry.evidenceTimeAttestationStore.authorityPolicyEnabled),
      policyCompliantAttestations: policyCompliant.length,
      policyRejectedAttestations: attestations.length - policyCompliant.length,
      operationallyAcceptable: providerIds.length >= minimumProviders,
      operationalQuorumSatisfied: providerIds.length >= minimumProviders,
      acceptableAttestations: acceptable.length,
      acceptableDistinctProviders: providerIds.length,
      acceptableProviderIds: providerIds,
      rejectedAttestations: attestations.length - acceptable.length,
      attestationDecisions: attestations.map((attestation) => ({
        ...attestation,
        authorityPolicy: attestation.authorityPolicy ?? { trusted: true, reason: null },
        governance: publicDecision(evaluation.decisions.get(attestation.attestationId))
      }))
    };
  }

  function verifyEvidenceTimeAttestations(tenantId, archiveId) {
    return effectiveArchiveVerification(tenantId, archiveId);
  }

  function currentOperationalPosture(tenantId, evidenceId = null) {
    const items = evidenceId
      ? [registry.get(tenantId, evidenceId)]
      : registry.list(tenantId, { limit: 5000 });
    const missingPreservations = [];
    const missingOperationalQuorum = [];
    let totalVersions = 0;
    let preservedVersions = 0;
    let operationalQuorumVersions = 0;

    for (const item of items) {
      if (item.status === 'disposed') continue;
      for (const version of item.versions ?? []) {
        totalVersions += 1;
        const receipt = registry.evidencePreservationStore.verifiedForVersion(
          tenantId, item.evidenceId, version.version, version.sha256, item.retentionUntil
        );
        if (!receipt) {
          missingPreservations.push({ evidenceId: item.evidenceId, version: version.version });
          continue;
        }
        preservedVersions += 1;
        const verification = effectiveArchiveVerification(tenantId, receipt.archiveId);
        if (verification.operationalQuorumSatisfied) operationalQuorumVersions += 1;
        else {
          missingOperationalQuorum.push({
            evidenceId: item.evidenceId,
            version: version.version,
            archiveId: receipt.archiveId,
            acceptableDistinctProviders: verification.acceptableDistinctProviders,
            minimumProviders: verification.minimumProviders,
            rejectedAttestations: verification.rejectedAttestations,
            policyRejectedAttestations: verification.policyRejectedAttestations
          });
        }
      }
    }
    return {
      totalVersions,
      preservedVersions,
      operationalQuorumVersions,
      missingPreservations,
      missingOperationalQuorum
    };
  }

  function evidenceTimeAttestationGovernanceStatus(tenantId) {
    const base = registry.evidenceTimeAttestationStatus(tenantId);
    const journal = governance.tenantStatus(tenantId);
    if (!governance.enabled) return { ...journal, cryptographic: base };
    const recent = registry.evidenceTimeAttestationStore.list(tenantId, { limit: 5000 });
    const evaluation = governance.evaluate(tenantId, recent);
    const posture = currentOperationalPosture(tenantId);
    let acceptableAttestations = 0;
    let revokedAttestations = 0;
    let supersededAttestations = 0;
    let policyRejectedAttestations = 0;
    for (const attestation of recent) {
      if (attestation.authorityPolicy?.trusted === false) {
        policyRejectedAttestations += 1;
        continue;
      }
      const decision = evaluation.decisions.get(attestation.attestationId);
      if (decision?.operationallyAcceptable) acceptableAttestations += 1;
      else if (decision?.status === 'superseded') supersededAttestations += 1;
      else revokedAttestations += 1;
    }
    return {
      ...journal,
      cryptographic: base,
      evaluatedAttestations: recent.length,
      acceptableAttestations,
      policyRejectedAttestations,
      revokedAttestations,
      supersededAttestations,
      totalVersions: posture.totalVersions,
      preservedVersions: posture.preservedVersions,
      operationalQuorumVersions: posture.operationalQuorumVersions,
      missingPreservationCount: posture.missingPreservations.length,
      missingOperationalQuorumCount: posture.missingOperationalQuorum.length,
      dispositionReady: !governance.requiredForDisposition
        || (posture.missingPreservations.length === 0 && posture.missingOperationalQuorum.length === 0)
    };
  }

  function dispose(tenantId, evidenceId, input, context = {}) {
    if (governance.requiredForDisposition) {
      const item = registry.get(tenantId, evidenceId);
      const posture = currentOperationalPosture(tenantId, item.evidenceId);
      if (posture.missingPreservations.length || posture.missingOperationalQuorum.length) {
        throw new EvidenceTimeAttestationGovernanceRequiredError(item.evidenceId, {
          missingPreservations: posture.missingPreservations.map((entry) => entry.version),
          missingOperationalQuorum: posture.missingOperationalQuorum
        });
      }
    }
    return registry.dispose(tenantId, evidenceId, input, context);
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    const journal = governance.verifyTenant(tenantId);
    if (!evidenceId || !governance.enabled) return { ...base, timeAttestationGovernance: journal };
    const posture = currentOperationalPosture(tenantId, evidenceId);
    return {
      ...base,
      timeAttestationGovernance: {
        ...journal,
        checkedArchives: posture.preservedVersions,
        operationalQuorumArchives: posture.operationalQuorumVersions,
        missingPreservationCount: posture.missingPreservations.length,
        missingOperationalQuorumCount: posture.missingOperationalQuorum.length
      }
    };
  }

  function health() {
    const base = registry.health();
    const journal = governance.health();
    const unavailable = governance.requiredForDisposition && journal.status !== 'ready';
    return {
      ...base,
      required: Boolean(base.required || governance.requiredForDisposition),
      status: unavailable || base.status === 'unavailable' ? 'unavailable' : base.status,
      timeAttestationGovernance: journal
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const journal = evidenceTimeAttestationGovernanceStatus(tenantId);
      const unavailable = governance.requiredForDisposition && journal.status !== 'ready';
      const attention = governance.requiredForDisposition && !journal.dispositionReady;
      return {
        ...base,
        status: unavailable || base.status === 'unavailable'
          ? 'unavailable'
          : attention ? 'attention' : base.status,
        timeAttestationGovernance: journal
      };
    } catch (error) {
      return {
        ...base,
        status: governance.requiredForDisposition ? 'unavailable' : base.status,
        timeAttestationGovernance: {
          status: 'unavailable',
          enabled: governance.enabled,
          requiredForDisposition: governance.requiredForDisposition,
          error: error?.code ?? 'evidence_time_attestation_governance_store_unavailable'
        }
      };
    }
  }

  return Object.freeze({
    ...registry,
    recordTimeAttestation,
    verifyEvidenceTimeAttestations,
    dispose,
    verify,
    health,
    tenantStatus,
    recordTimeAttestationGovernanceEvent,
    evidenceTimeAttestationGovernanceEvents,
    verifyEvidenceTimeAttestationGovernance,
    evidenceTimeAttestationGovernanceStatus,
    effectiveArchiveVerification,
    evidenceTimeAttestationGovernanceEnabled: governance.enabled,
    evidenceTimeAttestationGovernanceStore: governance
  });
}

export function createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationRegistryFromEnvironment(env);
  const governance = createEvidenceTimeAttestationGovernanceStoreFromEnvironment({ env });
  if (governance.requiredForDisposition && !registry.evidenceTimeAttestationEnabled) {
    throw new TypeError('Required time-attestation governance needs enabled time attestations.');
  }
  return createEvidenceTimeAttestationGovernanceRegistry({ registry, governance });
}

function publicDecision(decision) {
  if (!decision) return {
    cryptographicallyValid: true,
    operationallyAcceptable: true,
    status: 'acceptable',
    reasons: []
  };
  return {
    cryptographicallyValid: decision.cryptographicallyValid,
    operationallyAcceptable: decision.operationallyAcceptable,
    status: decision.status,
    reasons: decision.reasons
  };
}
