import { sha256 } from './evidenceCrypto.js';
import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationGovernanceRegistryFromEnvironment } from './evidenceTimeAttestationGovernanceRegistry.js';
import {
  createEvidenceDisclosureBundleStore,
  createEvidenceDisclosureBundleStoreFromEnvironment
} from './evidenceDisclosureBundleStore.js';

export function createEvidenceDisclosureRegistry({
  registry,
  disclosures = createEvidenceDisclosureBundleStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.verifyEvidenceTimeAttestations !== 'function'
      || typeof registry.verify !== 'function' || typeof registry.effectiveArchiveVerification !== 'function') {
    throw new TypeError('A governed time-attestation-aware evidence registry is required.');
  }
  if (!disclosures || typeof disclosures.create !== 'function') throw new TypeError('An evidence disclosure store is required.');

  function createDisclosureBundle(tenantId, evidenceId, input = {}, context = {}) {
    if (!disclosures.enabled) throw new EvidenceConflictError('Evidence disclosures are disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A disclosure request is required.');
    const item = registry.get(tenantId, evidenceId);
    if (input.confirmation !== `CREATE DISCLOSURE ${item.evidenceId}`) {
      throw new EvidenceValidationError(`confirmation must be exactly CREATE DISCLOSURE ${item.evidenceId}.`, { field: 'confirmation' });
    }
    const recipientId = identifier(input.recipientId, 'recipientId');
    const idempotencyKey = identifier(input.idempotencyKey, 'idempotencyKey');
    const purpose = cleanText(input.purpose, 'purpose', 10, 500);
    const includeFilenames = input.includeFilenames === true;
    const selectedVersions = normaliseVersions(input.versions, item.versions);
    const fullVerification = registry.verify(tenantId, item.evidenceId);

    const versions = selectedVersions.map((versionNumber) => {
      const metadata = item.versions.find((entry) => entry.version === versionNumber);
      if (!metadata) throw new EvidenceValidationError('A requested disclosure version does not exist.', { field: 'version', version: versionNumber });
      const screening = safeScreeningReport(tenantId, item.evidenceId, versionNumber);
      const externalScans = safeExternalScans(tenantId, item.evidenceId, versionNumber);
      const receipt = registry.evidencePreservationStore.verifiedForVersion(
        tenantId,
        item.evidenceId,
        metadata.version,
        metadata.sha256,
        item.retentionUntil
      );
      if (!receipt) {
        throw new EvidenceConflictError('Every disclosed evidence version requires a verified preservation receipt.', {
          evidenceId: item.evidenceId,
          version: metadata.version
        });
      }
      const notaryVerification = registry.effectiveArchiveVerification(tenantId, receipt.archiveId);
      if (!notaryVerification.operationalQuorumSatisfied) {
        throw new EvidenceConflictError('Every disclosed evidence version requires the configured operationally acceptable notary quorum.', {
          evidenceId: item.evidenceId,
          version: metadata.version,
          archiveId: receipt.archiveId,
          acceptableDistinctProviders: notaryVerification.acceptableDistinctProviders,
          minimumProviders: notaryVerification.minimumProviders
        });
      }
      const timeAttestations = safeTimeAttestationDecisions(notaryVerification);
      return {
        version: metadata.version,
        filename: includeFilenames ? metadata.filename ?? item.filename ?? null : null,
        mediaType: metadata.mediaType ?? item.mediaType ?? null,
        sizeBytes: metadata.sizeBytes,
        contentSha256: metadata.sha256,
        createdAt: metadata.createdAt ?? null,
        screening,
        externalScans,
        preservationReceipt: receipt,
        timeAttestations,
        timeAttestationVerification: sanitiseNotaryVerification(notaryVerification)
      };
    });

    const payloadBody = {
      tenantReference: sha256(String(tenantId)),
      evidence: {
        evidenceReference: item.evidenceId,
        status: item.status,
        currentVersion: item.currentVersion,
        retentionUntil: item.retentionUntil,
        legalHoldActive: Boolean(item.legalHold?.active),
        filenameIncluded: includeFilenames,
        versions
      },
      integrity: {
        registryVerification: sanitiseVerification(fullVerification),
        versionCount: versions.length,
        allVersionsPreserved: true,
        allVersionsTimeAttested: true,
        allVersionsOperationallyAcceptable: true,
        notaryGovernanceEvaluated: true,
        rawEvidenceIncluded: false
      }
    };

    return disclosures.create({
      tenantId,
      evidenceId: item.evidenceId,
      recipientId,
      idempotencyKey,
      purpose,
      expiresAt: input.expiresAt,
      payloadBody
    }, { actor: context.actor });
  }

  function disclosureBundles(tenantId, evidenceId, options = {}) {
    registry.get(tenantId, evidenceId);
    return disclosures.list(tenantId, { evidenceId, ...options });
  }

  function disclosurePackage(tenantId, bundleId) {
    return disclosures.packageFor(tenantId, bundleId);
  }

  function verifyDisclosureBundle(tenantId, bundleId) {
    return disclosures.verify(tenantId, bundleId);
  }

  function disclosureStatus(tenantId) {
    const base = disclosures.tenantStatus(tenantId);
    if (!disclosures.enabled) return base;
    const records = disclosures.list(tenantId, { limit: 5000 });
    const currentTime = Date.now();
    return {
      ...base,
      activeBundles: records.filter((record) => new Date(record.expiresAt).getTime() > currentTime).length,
      expiredBundles: records.filter((record) => new Date(record.expiresAt).getTime() <= currentTime).length,
      metadataOnly: true,
      offlineVerificationSupported: true,
      operationalNotaryGovernanceRequired: true
    };
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    if (!disclosures.enabled) return { ...base, disclosures: { valid: true, enabled: false } };
    if (evidenceId) {
      const records = disclosures.list(tenantId, { evidenceId, limit: 5000 });
      for (const record of records) disclosures.verify(tenantId, record.bundleId);
      return { ...base, disclosures: { valid: true, enabled: true, checkedBundles: records.length } };
    }
    return { ...base, disclosures: disclosures.verifyTenant(tenantId) };
  }

  function health() {
    const base = registry.health();
    const disclosure = disclosures.health();
    return {
      ...base,
      status: base.status === 'unavailable' || (disclosures.enabled && disclosure.status !== 'ready') ? 'unavailable' : base.status,
      disclosures: disclosure
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    const disclosure = disclosureStatus(tenantId);
    return {
      ...base,
      status: base.status === 'unavailable' || (disclosures.enabled && disclosure.status !== 'ready') ? 'unavailable' : base.status,
      disclosures: disclosure
    };
  }

  function safeScreeningReport(tenantId, evidenceId, version) {
    try {
      const report = registry.screeningReport(tenantId, evidenceId, { version });
      return {
        version: report.version,
        status: report.status ?? report.decision ?? null,
        screenedAt: report.screenedAt ?? null,
        engineVersion: report.engineVersion ?? null,
        findings: Array.isArray(report.findings)
          ? report.findings.map((finding) => ({ code: finding.code, severity: finding.severity, category: finding.category ?? null }))
          : []
      };
    } catch (error) {
      return { version, status: 'unavailable', error: error?.code ?? 'screening_report_unavailable', findings: [] };
    }
  }

  function safeExternalScans(tenantId, evidenceId, version) {
    if (typeof registry.externalScanAttestations !== 'function') return [];
    try {
      return registry.externalScanAttestations(tenantId, evidenceId, { version, limit: 1000 }).map((entry) => ({
        attestationId: entry.attestationId,
        providerId: entry.providerId,
        verdict: entry.verdict,
        scannedAt: entry.scannedAt,
        receivedAt: entry.receivedAt,
        contentSha256: entry.contentSha256,
        signatureKeyId: entry.keyId ?? entry.signatureKeyId ?? null,
        findingCodes: Array.isArray(entry.findings) ? entry.findings.map((finding) => finding.code) : []
      }));
    } catch (error) {
      return [{ status: 'unavailable', error: error?.code ?? 'external_scan_attestations_unavailable' }];
    }
  }

  return Object.freeze({
    ...registry,
    verify,
    health,
    tenantStatus,
    createDisclosureBundle,
    disclosureBundles,
    disclosurePackage,
    verifyDisclosureBundle,
    disclosureStatus,
    evidenceDisclosureEnabled: disclosures.enabled,
    evidenceDisclosureStore: disclosures
  });
}

export function createEvidenceDisclosureRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env);
  const disclosures = createEvidenceDisclosureBundleStoreFromEnvironment({ env, evidenceRegistry: registry });
  return createEvidenceDisclosureRegistry({ registry, disclosures });
}

function normaliseVersions(raw, versions) {
  const available = new Set((versions ?? []).map((entry) => entry.version));
  if (raw === undefined || raw === null) return [...available].sort((left, right) => left - right);
  if (!Array.isArray(raw) || !raw.length || raw.length > 1000) throw new EvidenceValidationError('versions must be a non-empty array with at most 1000 entries.', { field: 'versions' });
  const result = [...new Set(raw.map((value) => {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < 1 || !available.has(parsed)) throw new EvidenceValidationError('versions contains an unavailable evidence version.', { field: 'versions', version: value });
    return parsed;
  }))];
  return result.sort((left, right) => left - right);
}
function safeTimeAttestationDecisions(verification) {
  const records = Array.isArray(verification?.attestationDecisions) ? verification.attestationDecisions : [];
  return records.map((entry) => ({
    attestationId: entry.attestationId,
    archiveId: entry.archiveId,
    providerId: entry.providerId,
    keyId: entry.keyId,
    receiptSha256: entry.receiptSha256,
    objectEnvelopeSha256: entry.objectEnvelopeSha256,
    timestamp: entry.timestamp,
    policyId: entry.policyId,
    nonce: entry.nonce,
    sequence: entry.sequence,
    receivedAt: entry.receivedAt,
    previousHash: entry.previousHash,
    hash: entry.hash,
    governance: {
      cryptographicallyValid: entry.governance?.cryptographicallyValid !== false,
      operationallyAcceptable: Boolean(entry.governance?.operationallyAcceptable),
      status: entry.governance?.status ?? 'unknown',
      reasonCodes: Array.isArray(entry.governance?.reasons)
        ? entry.governance.reasons.map((reason) => reason.reasonCode ?? reason.code ?? reason.status).filter(Boolean)
        : []
    }
  }));
}
function sanitiseVerification(value) {
  return {
    valid: value?.valid !== false,
    evidenceId: value?.evidenceId ?? null,
    checkedVersions: value?.checkedVersions ?? value?.versions ?? null,
    custodyChainValid: value?.chain?.valid ?? value?.custody?.valid ?? true,
    preservationValid: value?.preservation?.valid ?? true,
    timeAttestationsValid: value?.timeAttestations?.valid ?? true,
    timeAttestationGovernanceValid: value?.timeAttestationGovernance?.valid ?? true
  };
}
function sanitiseNotaryVerification(value) {
  return {
    valid: value?.valid !== false,
    cryptographicallyValid: value?.cryptographicallyValid !== false,
    archiveId: value?.archiveId ?? null,
    attestationCount: value?.attestationCount ?? 0,
    distinctProviders: value?.distinctProviders ?? 0,
    minimumProviders: value?.minimumProviders ?? null,
    cryptographicQuorumSatisfied: Boolean(value?.quorumSatisfied),
    governanceEnabled: Boolean(value?.governanceEnabled),
    governanceEvaluatedAt: value?.governanceEvaluatedAt ?? null,
    governanceEventsConsidered: value?.governanceEventsConsidered ?? 0,
    operationalQuorumSatisfied: Boolean(value?.operationalQuorumSatisfied),
    acceptableAttestations: value?.acceptableAttestations ?? 0,
    acceptableDistinctProviders: value?.acceptableDistinctProviders ?? 0,
    acceptableProviderIds: value?.acceptableProviderIds ?? [],
    rejectedAttestations: value?.rejectedAttestations ?? 0
  };
}
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
