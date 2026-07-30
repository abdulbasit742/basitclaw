import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationGovernanceRegistryFromEnvironment } from './evidenceTimeAttestationGovernanceRegistry.js';
import {
  createEvidenceDisclosureStore,
  createEvidenceDisclosureStoreFromEnvironment
} from './evidenceDisclosureStore.js';

export class EvidenceDisclosurePrerequisiteError extends EvidenceConflictError {
  constructor(message, details = {}) {
    super(message, details);
    this.name = 'EvidenceDisclosurePrerequisiteError';
    this.code = 'EVIDENCE_DISCLOSURE_PREREQUISITE_REQUIRED';
  }
}

export function createEvidenceDisclosureRegistry({
  registry,
  disclosures = createEvidenceDisclosureStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.readContent !== 'function' || typeof registry.get !== 'function'
      || typeof registry.effectiveArchiveVerification !== 'function') {
    throw new TypeError('A time-attestation-governance-aware evidence registry is required.');
  }
  if (!disclosures || typeof disclosures.request !== 'function') throw new TypeError('An evidence disclosure store is required.');

  function requestEvidenceDisclosure(tenantId, evidenceId, input = {}, context = {}) {
    if (!disclosures.enabled) throw new EvidenceConflictError('Evidence disclosure is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A disclosure request is required.');
    const item = registry.get(tenantId, evidenceId);
    if (item.status === 'disposed') throw new EvidenceConflictError('Disposed evidence cannot be disclosed.', { evidenceId: item.evidenceId });
    const version = positiveInteger(input.version ?? item.currentVersion, 'version');
    const metadata = item.versions.find((entry) => entry.version === version);
    if (!metadata) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version', version });
    assertDisclosurePrerequisites(tenantId, item, metadata);
    registry.readContent(tenantId, item.evidenceId, { version });
    return disclosures.request({
      tenantId,
      evidenceId: item.evidenceId,
      evidenceVersion: version,
      contentSha256: metadata.sha256,
      sizeBytes: metadata.sizeBytes,
      recipientId: input.recipientId,
      residencyZone: input.residencyZone,
      purpose: input.purpose,
      expiresAt: input.expiresAt
    }, {
      actor: context.actor,
      role: context.role
    });
  }

  function approveEvidenceDisclosure(tenantId, disclosureId, context = {}) {
    return disclosures.approve(tenantId, disclosureId, {
      actor: context.actor,
      role: context.role,
      contentProvider: (disclosure) => {
        const item = registry.get(tenantId, disclosure.evidenceId);
        const metadata = item.versions.find((entry) => entry.version === disclosure.evidenceVersion);
        if (!metadata) throw new EvidenceIntegrityError('The disclosure evidence version no longer exists.', { disclosureId });
        if (metadata.sha256 !== disclosure.contentSha256 || metadata.sizeBytes !== disclosure.sizeBytes) {
          throw new EvidenceIntegrityError('Disclosure metadata no longer matches immutable evidence.', { disclosureId });
        }
        assertDisclosurePrerequisites(tenantId, item, metadata);
        const content = registry.readContent(tenantId, item.evidenceId, { version: metadata.version });
        return {
          content: content.content,
          filename: metadata.filename ?? item.filename,
          mediaType: metadata.mediaType ?? item.mediaType
        };
      }
    });
  }

  function revokeEvidenceDisclosure(tenantId, disclosureId, input = {}, context = {}) {
    return disclosures.revoke(tenantId, disclosureId, { actor: context.actor, reason: input.reason });
  }
  function claimEvidenceDisclosures(bodyBytes, headers) { return disclosures.claimSigned(bodyBytes, headers); }
  function acknowledgeEvidenceDisclosure(disclosureId, bodyBytes, headers) { return disclosures.acknowledgeSigned(disclosureId, bodyBytes, headers); }
  function evidenceDisclosure(tenantId, disclosureId) { return disclosures.get(tenantId, disclosureId); }
  function evidenceDisclosures(tenantId, options = {}) { return disclosures.list(tenantId, options); }
  function evidenceDisclosureReport(tenantId) { return disclosures.report(tenantId); }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    if (!disclosures.enabled) return { ...base, disclosures: { valid: true, enabled: false } };
    return { ...base, disclosures: disclosures.verifyTenant(tenantId) };
  }

  function health() {
    const base = registry.health();
    const disclosure = disclosures.health();
    return {
      ...base,
      status: disclosure.status === 'unavailable' || base.status === 'unavailable' ? 'unavailable' : base.status,
      disclosures: disclosure
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const report = evidenceDisclosureReport(tenantId);
      const attention = (report.byState.requested ?? 0) > 0 || (report.byState.claimed ?? 0) > 0 || (report.byState.dead_letter ?? 0) > 0;
      return {
        ...base,
        status: base.status === 'unavailable' ? 'unavailable' : attention ? 'attention' : base.status,
        disclosures: { status: 'ready', enabled: disclosures.enabled, ...report }
      };
    } catch (error) {
      return {
        ...base,
        status: disclosures.enabled ? 'unavailable' : base.status,
        disclosures: { status: 'unavailable', enabled: disclosures.enabled, error: error?.code ?? 'evidence_disclosure_store_unavailable' }
      };
    }
  }

  function assertDisclosurePrerequisites(tenantId, item, version) {
    if (!registry.evidencePreservationEnabled) {
      throw new EvidenceDisclosurePrerequisiteError('Evidence disclosure requires immutable preservation.', {
        evidenceId: item.evidenceId, version: version.version, prerequisite: 'preservation'
      });
    }
    const receipt = registry.evidencePreservationStore.verifiedForVersion(
      tenantId, item.evidenceId, version.version, version.sha256, item.retentionUntil
    );
    if (!receipt) {
      throw new EvidenceDisclosurePrerequisiteError('The evidence version must have a verified preservation receipt before disclosure.', {
        evidenceId: item.evidenceId, version: version.version, prerequisite: 'preservation'
      });
    }
    if (!registry.evidenceTimeAttestationEnabled || !registry.evidenceTimeAttestationGovernanceEnabled) {
      throw new EvidenceDisclosurePrerequisiteError('Evidence disclosure requires enabled independent time attestations and operational governance.', {
        evidenceId: item.evidenceId,
        version: version.version,
        archiveId: receipt.archiveId,
        prerequisite: 'time_attestation_governance'
      });
    }
    const verification = registry.effectiveArchiveVerification(tenantId, receipt.archiveId);
    if (!verification.operationalQuorumSatisfied) {
      throw new EvidenceDisclosurePrerequisiteError('The preservation receipt must satisfy operationally acceptable time-attestation quorum before disclosure.', {
        evidenceId: item.evidenceId,
        version: version.version,
        archiveId: receipt.archiveId,
        prerequisite: 'operational_time_attestation_quorum',
        minimumProviders: verification.minimumProviders,
        acceptableDistinctProviders: verification.acceptableDistinctProviders,
        rejectedAttestations: verification.rejectedAttestations
      });
    }
    return { receipt, verification };
  }

  return Object.freeze({
    ...registry,
    verify,
    health,
    tenantStatus,
    requestEvidenceDisclosure,
    approveEvidenceDisclosure,
    revokeEvidenceDisclosure,
    claimEvidenceDisclosures,
    acknowledgeEvidenceDisclosure,
    evidenceDisclosure,
    evidenceDisclosures,
    evidenceDisclosureReport,
    evidenceDisclosureEnabled: disclosures.enabled,
    evidenceDisclosureStore: disclosures
  });
}

export function createEvidenceDisclosureRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env);
  const disclosures = createEvidenceDisclosureStoreFromEnvironment({ env });
  if (disclosures.enabled && (!registry.evidencePreservationEnabled
      || !registry.evidenceTimeAttestationEnabled || !registry.evidenceTimeAttestationGovernanceEnabled)) {
    throw new TypeError('Governed evidence disclosure requires preservation, time attestations and notary governance.');
  }
  return createEvidenceDisclosureRegistry({ registry, disclosures });
}

function positiveInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) {
    throw new EvidenceValidationError(`${field} must be a positive integer.`, { field });
  }
  return parsed;
}
