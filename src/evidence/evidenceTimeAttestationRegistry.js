import { sha256 } from './evidenceCrypto.js';
import { EvidenceConflictError } from './evidenceRegistry.js';
import { createEvidencePreservationRegistryFromEnvironment } from './evidencePreservationRegistry.js';
import {
  EvidenceTimeAttestationRequiredError,
  createEvidenceTimeAttestationStore,
  createEvidenceTimeAttestationStoreFromEnvironment
} from './evidenceTimeAttestationStore.js';

const RECEIPT_CHALLENGE_FORMAT = 'basitclaw-preservation-receipt-challenge-v1';

export function createEvidenceTimeAttestationRegistry({
  registry,
  timeAttestations = createEvidenceTimeAttestationStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.verifyEvidencePreservation !== 'function' || typeof registry.dispose !== 'function') {
    throw new TypeError('A preservation-aware evidence registry is required.');
  }
  if (!timeAttestations || typeof timeAttestations.record !== 'function') {
    throw new TypeError('An evidence time-attestation store is required.');
  }

  function timeAttestationChallenge(tenantId, archiveId) {
    const verified = registry.verifyEvidencePreservation(tenantId, archiveId);
    return challengeFromVerification(tenantId, verified);
  }

  function recordTimeAttestation(input) {
    if (!timeAttestations.enabled) throw new EvidenceConflictError('Evidence time attestations are disabled.');
    return timeAttestations.record(input);
  }

  function evidenceTimeAttestations(tenantId, archiveId, options = {}) {
    registry.verifyEvidencePreservation(tenantId, archiveId);
    return timeAttestations.list(tenantId, { archiveId, ...options });
  }

  function verifyEvidenceTimeAttestations(tenantId, archiveId) {
    registry.verifyEvidencePreservation(tenantId, archiveId);
    return timeAttestations.verifyArchive(tenantId, archiveId);
  }

  function evidenceTimeAttestationStatus(tenantId) {
    const base = timeAttestations.tenantStatus(tenantId);
    if (!timeAttestations.enabled) return base;
    const items = registry.list(tenantId, { limit: 5000 });
    const preserved = [];
    const missingPreservations = [];
    for (const item of items) {
      if (item.status === 'disposed') continue;
      for (const version of item.versions ?? []) {
        const receipt = registry.evidencePreservationStore.verifiedForVersion(
          tenantId, item.evidenceId, version.version, version.sha256, item.retentionUntil
        );
        if (!receipt) {
          missingPreservations.push({ evidenceId: item.evidenceId, version: version.version });
          continue;
        }
        preserved.push({ item, version, receipt });
      }
    }
    const quorumByArchive = timeAttestations.quorumForArchives(
      tenantId,
      preserved.map((entry) => entry.receipt.archiveId)
    );
    const missingQuorum = [];
    let quorumVersions = 0;
    for (const entry of preserved) {
      if (quorumByArchive.get(entry.receipt.archiveId)) quorumVersions += 1;
      else {
        missingQuorum.push({
          evidenceId: entry.item.evidenceId,
          version: entry.version.version,
          archiveId: entry.receipt.archiveId
        });
      }
    }
    return {
      ...base,
      preservedVersions: preserved.length,
      quorumVersions,
      missingPreservationCount: missingPreservations.length,
      missingQuorumCount: missingQuorum.length,
      dispositionReady: !timeAttestations.requiredForDisposition
        || (missingPreservations.length === 0 && missingQuorum.length === 0)
    };
  }

  function dispose(tenantId, evidenceId, input, context = {}) {
    if (timeAttestations.requiredForDisposition) {
      const item = registry.get(tenantId, evidenceId);
      const preserved = [];
      const missingPreservations = [];
      for (const version of item.versions ?? []) {
        const receipt = registry.evidencePreservationStore.verifiedForVersion(
          tenantId, item.evidenceId, version.version, version.sha256, item.retentionUntil
        );
        if (!receipt) missingPreservations.push(version.version);
        else preserved.push({ version: version.version, receipt });
      }
      const quorumByArchive = timeAttestations.quorumForArchives(
        tenantId,
        preserved.map((entry) => entry.receipt.archiveId)
      );
      const missingQuorum = preserved
        .filter((entry) => !quorumByArchive.get(entry.receipt.archiveId))
        .map((entry) => ({ version: entry.version, archiveId: entry.receipt.archiveId }));
      if (missingPreservations.length || missingQuorum.length) {
        throw new EvidenceTimeAttestationRequiredError(item.evidenceId, {
          minimumProviders: timeAttestations.minimumProviders,
          missingPreservations,
          missingQuorum
        });
      }
    }
    return registry.dispose(tenantId, evidenceId, input, context);
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    if (!timeAttestations.enabled) return { ...base, timeAttestations: { valid: true, enabled: false } };
    if (!evidenceId) return { ...base, timeAttestations: timeAttestations.verifyTenant(tenantId) };
    const receipts = registry.evidencePreservationReceipts(tenantId, evidenceId, { limit: 100_000 });
    const batch = timeAttestations.verifyArchives(tenantId, receipts.map((receipt) => receipt.archiveId));
    const results = [...batch.results.values()];
    return {
      ...base,
      timeAttestations: {
        valid: true,
        enabled: true,
        checkedArchives: results.length,
        checkedAttestations: batch.checkedAttestations,
        quorumArchives: results.filter((result) => result.quorumSatisfied).length
      }
    };
  }

  function health() {
    const base = registry.health();
    const notary = timeAttestations.health();
    const unavailable = timeAttestations.requiredForDisposition && notary.status !== 'ready';
    return {
      ...base,
      required: Boolean(base.required || timeAttestations.requiredForDisposition),
      status: unavailable || base.status === 'unavailable' ? 'unavailable' : base.status,
      timeAttestations: notary
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const notary = evidenceTimeAttestationStatus(tenantId);
      const unavailable = timeAttestations.requiredForDisposition && notary.status !== 'ready';
      const attention = timeAttestations.requiredForDisposition && !notary.dispositionReady;
      return {
        ...base,
        status: unavailable ? 'unavailable' : base.status === 'unavailable' ? 'unavailable' : attention ? 'attention' : base.status,
        timeAttestations: notary
      };
    } catch (error) {
      return {
        ...base,
        status: timeAttestations.requiredForDisposition ? 'unavailable' : base.status,
        timeAttestations: {
          status: 'unavailable', enabled: timeAttestations.enabled,
          requiredForDisposition: timeAttestations.requiredForDisposition,
          error: error?.code ?? 'evidence_time_attestation_store_unavailable'
        }
      };
    }
  }

  return Object.freeze({
    ...registry,
    dispose,
    verify,
    health,
    tenantStatus,
    timeAttestationChallenge,
    recordTimeAttestation,
    evidenceTimeAttestations,
    verifyEvidenceTimeAttestations,
    evidenceTimeAttestationStatus,
    evidenceTimeAttestationEnabled: timeAttestations.enabled,
    evidenceTimeAttestationStore: timeAttestations
  });
}

export function createEvidenceTimeAttestationRegistryFromEnvironment(env = process.env) {
  const registry = createEvidencePreservationRegistryFromEnvironment(env);
  const resolveChallenge = (tenantId, archiveId) => {
    const verified = registry.verifyEvidencePreservation(tenantId, archiveId);
    return challengeFromVerification(tenantId, verified);
  };
  const timeAttestations = createEvidenceTimeAttestationStoreFromEnvironment({ env, resolveChallenge });
  return createEvidenceTimeAttestationRegistry({ registry, timeAttestations });
}

export function preservationReceiptChallengeDigest(receipt) {
  const stable = {
    format: RECEIPT_CHALLENGE_FORMAT,
    receiptId: receipt.receiptId,
    archiveId: receipt.archiveId,
    evidenceId: receipt.evidenceId,
    evidenceVersion: receipt.evidenceVersion,
    contentSha256: receipt.contentSha256,
    sizeBytes: receipt.sizeBytes,
    objectEnvelopeSha256: receipt.objectEnvelopeSha256,
    retentionUntil: receipt.retentionUntil,
    archivedAt: receipt.archivedAt,
    immutabilityMode: receipt.immutabilityMode,
    signingKeyId: receipt.signingKeyId,
    signature: receipt.signature
  };
  return sha256(stableStringify(stable));
}

function challengeFromVerification(tenantId, verified) {
  const receipt = verified.receipt;
  return {
    tenantId,
    archiveId: verified.archiveId,
    receiptSha256: preservationReceiptChallengeDigest(receipt),
    objectEnvelopeSha256: receipt.objectEnvelopeSha256,
    archivedAt: receipt.archivedAt,
    retentionUntil: receipt.retentionUntil
  };
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
