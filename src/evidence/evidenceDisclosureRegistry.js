import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { preservationReceiptChallengeDigest } from './evidenceTimeAttestationRegistry.js';
import { createEvidenceTimeAttestationRegistryFromEnvironment } from './evidenceTimeAttestationRegistry.js';
import {
  createEvidenceDisclosureStore,
  createEvidenceDisclosureStoreFromEnvironment
} from './evidenceDisclosureStore.js';

export function createEvidenceDisclosureRegistry({
  registry,
  disclosure = createEvidenceDisclosureStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.readContent !== 'function' || typeof registry.get !== 'function') {
    throw new TypeError('An evidence custody registry is required.');
  }
  if (!disclosure || typeof disclosure.createRequest !== 'function') {
    throw new TypeError('An evidence disclosure store is required.');
  }

  function createEvidenceDisclosure(tenantId, input, context = {}) {
    return disclosure.createRequest(input, {
      tenantId,
      actor: context.actor
    });
  }

  function approveEvidenceDisclosure(tenantId, requestId, input, context = {}) {
    return disclosure.approve(tenantId, requestId, input, { actor: context.actor });
  }

  function rejectEvidenceDisclosure(tenantId, requestId, input, context = {}) {
    return disclosure.reject(tenantId, requestId, input, { actor: context.actor });
  }

  function revokeEvidenceDisclosure(tenantId, requestId, input, context = {}) {
    return disclosure.revoke(tenantId, requestId, input, { actor: context.actor });
  }

  function evidenceDisclosures(tenantId, options = {}) {
    return disclosure.list(tenantId, options);
  }

  function evidenceDisclosure(tenantId, requestId) {
    return disclosure.get(tenantId, requestId);
  }

  function evidenceDisclosurePackage(tenantId, requestId) {
    return disclosure.sealedPackage(tenantId, requestId);
  }

  function evidenceDisclosureEvents(tenantId, requestId = null, options = {}) {
    return disclosure.events(tenantId, requestId, options);
  }

  function verifyEvidenceDisclosures(tenantId) {
    return disclosure.verifyTenant(tenantId);
  }

  function evidenceDisclosureStatus(tenantId) {
    return disclosure.tenantStatus(tenantId);
  }

  function health() {
    const base = registry.health();
    const sharing = disclosure.health();
    return {
      ...base,
      status: base.status === 'unavailable' ? 'unavailable' : sharing.status === 'unavailable' ? 'attention' : base.status,
      disclosures: sharing
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    const sharing = evidenceDisclosureStatus(tenantId);
    return {
      ...base,
      status: base.status === 'unavailable' ? 'unavailable' : sharing.status === 'unavailable' ? 'attention' : base.status,
      disclosures: sharing
    };
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    return {
      ...base,
      disclosures: disclosure.enabled
        ? disclosure.verifyTenant(tenantId)
        : { valid: true, enabled: false }
    };
  }

  return Object.freeze({
    ...registry,
    health,
    tenantStatus,
    verify,
    createEvidenceDisclosure,
    approveEvidenceDisclosure,
    rejectEvidenceDisclosure,
    revokeEvidenceDisclosure,
    evidenceDisclosures,
    evidenceDisclosure,
    evidenceDisclosurePackage,
    evidenceDisclosureEvents,
    verifyEvidenceDisclosures,
    evidenceDisclosureStatus,
    evidenceDisclosureEnabled: disclosure.enabled,
    evidenceDisclosureStore: disclosure
  });
}

export function createEvidenceDisclosureRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationRegistryFromEnvironment(env);
  const requirePreservation = parseBoolean(
    environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_PRESERVATION) ?? true
  );
  const requireTimeAttestation = parseBoolean(
    environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_TIME_ATTESTATION) ?? false
  );
  if (requireTimeAttestation && !requirePreservation) {
    throw new EvidenceValidationError('Disclosure time-attestation requirements also require preservation.', {
      field: 'WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_PRESERVATION'
    });
  }

  const resolveEvidence = (tenantId, selection) => {
    const item = registry.get(tenantId, selection.evidenceId);
    if (item.status === 'disposed') {
      throw new EvidenceConflictError('Disposed evidence cannot be disclosed.', {
        evidenceId: selection.evidenceId
      });
    }
    const version = item.versions?.find((entry) => entry.version === selection.version);
    if (!version) {
      throw new EvidenceValidationError('The requested disclosure evidence version does not exist.', {
        evidenceId: selection.evidenceId,
        version: selection.version
      });
    }
    const content = registry.readContent(tenantId, selection.evidenceId, {
      version: selection.version
    });
    if (content.sha256 !== version.sha256 || content.sizeBytes !== version.sizeBytes) {
      throw new EvidenceConflictError('The disclosure evidence no longer matches its immutable metadata.', {
        evidenceId: selection.evidenceId,
        version: selection.version
      });
    }

    let preservation = null;
    if (registry.evidencePreservationStore?.enabled) {
      preservation = registry.evidencePreservationStore.verifiedForVersion(
        tenantId,
        item.evidenceId,
        version.version,
        version.sha256,
        item.retentionUntil
      );
    }
    if (requirePreservation && !preservation) {
      throw new EvidenceConflictError('A verified current preservation receipt is required before disclosure.', {
        evidenceId: item.evidenceId,
        version: version.version,
        reason: 'preservation_required'
      });
    }

    let timeVerification = null;
    if (preservation && registry.evidenceTimeAttestationStore?.enabled) {
      timeVerification = registry.evidenceTimeAttestationStore.quorumForArchive(
        tenantId,
        preservation.archiveId
      );
    }
    if (requireTimeAttestation && !timeVerification) {
      throw new EvidenceConflictError('Independent time-attestation quorum is required before disclosure.', {
        evidenceId: item.evidenceId,
        version: version.version,
        archiveId: preservation?.archiveId ?? null,
        reason: 'time_attestation_required'
      });
    }

    return {
      evidenceId: item.evidenceId,
      version: version.version,
      filename: version.filename ?? item.filename,
      mediaType: version.mediaType ?? item.mediaType,
      contentSha256: version.sha256,
      sizeBytes: version.sizeBytes,
      preservationArchiveId: preservation?.archiveId ?? null,
      preservationReceiptSha256: preservation
        ? preservationReceiptChallengeDigest(preservation)
        : null,
      timeAttestationProviders: timeVerification?.providerIds ?? [],
      content: content.content
    };
  };

  const disclosure = createEvidenceDisclosureStoreFromEnvironment({ env, resolveEvidence });
  if (disclosure.enabled && requirePreservation && !registry.evidencePreservationEnabled) {
    throw new EvidenceConflictError('Evidence disclosure requires enabled immutable preservation.', {
      reason: 'preservation_disabled'
    });
  }
  if (disclosure.enabled && requireTimeAttestation && !registry.evidenceTimeAttestationEnabled) {
    throw new EvidenceConflictError('Evidence disclosure requires enabled independent time attestations.', {
      reason: 'time_attestation_disabled'
    });
  }
  return createEvidenceDisclosureRegistry({ registry, disclosure });
}

function parseBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  throw new TypeError('Boolean environment value must be true or false.');
}

function environmentValue(value) {
  const clean = typeof value === 'string' ? value.trim() : value;
  return clean === '' || clean === undefined || clean === null ? undefined : clean;
}
