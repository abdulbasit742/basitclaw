import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import { createExternalScanEvidenceRegistryFromEnvironment } from './externalScanEvidenceRegistry.js';
import {
  EvidencePreservationRequiredError,
  createEvidencePreservationStore,
  createEvidencePreservationStoreFromEnvironment
} from './evidencePreservationStore.js';

export function createEvidencePreservationRegistry({
  registry,
  preservation = createEvidencePreservationStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.readContent !== 'function' || typeof registry.dispose !== 'function') {
    throw new TypeError('An evidence registry with content and disposition support is required.');
  }
  if (!preservation || typeof preservation.preserve !== 'function') {
    throw new TypeError('An evidence preservation store is required.');
  }

  function preserveEvidence(tenantId, evidenceId, input = {}, context = {}) {
    if (!preservation.enabled) throw new EvidenceConflictError('Evidence preservation is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid evidence preservation request is required.');
    }
    const item = registry.get(tenantId, evidenceId);
    if (item.status === 'disposed') throw new EvidenceConflictError('Disposed evidence cannot be newly preserved.', { evidenceId });
    const version = input.version === undefined || input.version === null
      ? item.currentVersion
      : positiveInteger(input.version, 'version');
    const metadata = item.versions.find((entry) => entry.version === version);
    if (!metadata) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version', version });
    if (input.confirmation !== `PRESERVE ${item.evidenceId} V${version}`) {
      throw new EvidenceValidationError(`confirmation must be exactly PRESERVE ${item.evidenceId} V${version}.`, { field: 'confirmation' });
    }
    const purpose = cleanText(input.purpose, 'purpose', 10, 500);
    const content = registry.readContent(tenantId, item.evidenceId, { version });
    if (content.sha256 !== metadata.sha256 || content.sizeBytes !== metadata.sizeBytes) {
      throw new EvidenceIntegrityError('Preservation content does not match immutable evidence metadata.', {
        evidenceId: item.evidenceId,
        version
      });
    }
    return preservation.preserve({
      tenantId,
      evidenceId: item.evidenceId,
      version,
      filename: metadata.filename ?? item.filename,
      mediaType: metadata.mediaType ?? item.mediaType,
      contentSha256: metadata.sha256,
      sizeBytes: metadata.sizeBytes,
      retentionUntil: item.retentionUntil,
      legalHold: item.legalHold,
      content: content.content
    }, {
      actor: context.actor,
      purpose
    });
  }

  function evidencePreservationReceipts(tenantId, evidenceId, options = {}) {
    registry.get(tenantId, evidenceId);
    return preservation.list(tenantId, { evidenceId, ...options });
  }

  function verifyEvidencePreservation(tenantId, archiveId) {
    return preservation.verify(tenantId, archiveId);
  }

  function evidencePreservationStatus(tenantId) {
    const base = preservation.tenantStatus(tenantId);
    if (!preservation.enabled) return base;
    const items = registry.list(tenantId, { limit: 5000 });
    let totalVersions = 0;
    let preservedVersions = 0;
    for (const item of items) {
      if (item.status === 'disposed') continue;
      for (const version of item.versions) {
        totalVersions += 1;
        if (preservation.verifiedForVersion(
          tenantId,
          item.evidenceId,
          version.version,
          version.sha256,
          item.retentionUntil
        )) preservedVersions += 1;
      }
    }
    return {
      ...base,
      totalVersions,
      preservedVersions,
      unpreservedVersions: totalVersions - preservedVersions,
      dispositionReady: !preservation.requiredForDisposition || totalVersions === preservedVersions
    };
  }

  function dispose(tenantId, evidenceId, input, context = {}) {
    if (preservation.requiredForDisposition) {
      const item = registry.get(tenantId, evidenceId);
      const missingVersions = [];
      for (const version of item.versions) {
        const receipt = preservation.verifiedForVersion(
          tenantId,
          item.evidenceId,
          version.version,
          version.sha256,
          item.retentionUntil
        );
        if (!receipt) missingVersions.push(version.version);
      }
      if (missingVersions.length) {
        throw new EvidencePreservationRequiredError(item.evidenceId, {
          missingVersions,
          retentionUntil: item.retentionUntil
        });
      }
    }
    return registry.dispose(tenantId, evidenceId, input, context);
  }

  function get(tenantId, evidenceId) {
    return withPreservation(tenantId, registry.get(tenantId, evidenceId));
  }

  function list(tenantId, options = {}) {
    return registry.list(tenantId, options).map((item) => withPreservation(tenantId, item));
  }

  function screeningReport(tenantId, evidenceId, options = {}) {
    const report = registry.screeningReport(tenantId, evidenceId, options);
    return {
      ...report,
      preservationReceipts: preservation.list(tenantId, { evidenceId, limit: 5000 })
        .filter((receipt) => receipt.evidenceVersion === report.version)
    };
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    const preservationResult = evidenceId
      ? verifyEvidenceReceipts(tenantId, evidenceId)
      : preservation.verifyTenant(tenantId);
    return { ...base, preservation: preservationResult };
  }

  function verifyEvidenceReceipts(tenantId, evidenceId) {
    const receipts = preservation.list(tenantId, { evidenceId, limit: 5000 });
    for (const receipt of receipts) preservation.verify(tenantId, receipt.archiveId);
    return { valid: true, tenantId, evidenceId, checkedArchives: receipts.length };
  }

  function health() {
    const base = registry.health();
    const archive = preservation.health();
    const unavailable = preservation.requiredForDisposition && archive.status !== 'ready';
    const attention = preservation.enabled && archive.status === 'attention';
    return {
      ...base,
      required: Boolean(base.required || preservation.requiredForDisposition),
      status: unavailable ? 'unavailable' : base.status === 'unavailable' ? 'unavailable' : attention ? 'attention' : base.status,
      preservation: archive
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const archive = evidencePreservationStatus(tenantId);
      const unavailable = preservation.requiredForDisposition && archive.status !== 'ready';
      const attention = archive.status === 'attention' || (preservation.requiredForDisposition && !archive.dispositionReady);
      return {
        ...base,
        status: unavailable ? 'unavailable' : base.status === 'unavailable' ? 'unavailable' : attention ? 'attention' : base.status,
        preservation: archive
      };
    } catch (error) {
      return {
        ...base,
        status: preservation.requiredForDisposition ? 'unavailable' : base.status,
        preservation: {
          status: 'unavailable',
          enabled: preservation.enabled,
          requiredForDisposition: preservation.requiredForDisposition,
          error: error?.code ?? 'evidence_preservation_store_unavailable'
        }
      };
    }
  }

  function withPreservation(tenantId, item) {
    if (!item) return item;
    const receipts = preservation.list(tenantId, { evidenceId: item.evidenceId, limit: 5000 });
    const readyVersions = new Set();
    for (const version of item.versions ?? []) {
      if (receipts.some((receipt) => receipt.evidenceVersion === version.version
          && receipt.contentSha256 === version.sha256
          && new Date(receipt.retentionUntil) >= new Date(item.retentionUntil))) {
        readyVersions.add(version.version);
      }
    }
    return {
      ...item,
      preservation: {
        enabled: preservation.enabled,
        requiredForDisposition: preservation.requiredForDisposition,
        totalReceipts: receipts.length,
        preservedVersions: readyVersions.size,
        totalVersions: item.versions?.length ?? 0,
        dispositionReady: !preservation.requiredForDisposition || readyVersions.size === (item.versions?.length ?? 0),
        latestReceipt: receipts[0] ?? null
      }
    };
  }

  return Object.freeze({
    ...registry,
    get,
    list,
    screeningReport,
    dispose,
    verify,
    health,
    tenantStatus,
    preserveEvidence,
    evidencePreservationReceipts,
    verifyEvidencePreservation,
    evidencePreservationStatus,
    evidencePreservationEnabled: preservation.enabled,
    evidencePreservationStore: preservation
  });
}

export function createEvidencePreservationRegistryFromEnvironment(env = process.env) {
  const registry = createExternalScanEvidenceRegistryFromEnvironment(env);
  const preservation = createEvidencePreservationStoreFromEnvironment({ env, evidenceRegistry: registry });
  return createEvidencePreservationRegistry({ registry, preservation });
}

function positiveInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) {
    throw new EvidenceValidationError(`${field} must be a positive integer.`, { field });
  }
  return parsed;
}
function cleanText(value, field, minimum, maximum) {
  const text = String(value ?? '').trim();
  if (text.length < minimum || text.length > maximum) {
    throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field });
  }
  return text;
}
