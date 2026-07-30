import { sha256 } from './evidenceCrypto.js';
import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationGovernanceRegistryFromEnvironment } from './evidenceTimeAttestationGovernanceRegistry.js';
import {
  createEvidenceAssuranceBundleStore,
  createEvidenceAssuranceBundleStoreFromEnvironment
} from './evidenceAssuranceBundleStore.js';

const MANIFEST_FORMAT = 'basitclaw-assurance-bundle-manifest';

export function createEvidenceAssuranceBundleRegistry({
  registry,
  bundles = createEvidenceAssuranceBundleStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.readContent !== 'function' || typeof registry.events !== 'function') {
    throw new TypeError('A governed time-attestation-aware evidence registry is required.');
  }
  if (!bundles || typeof bundles.queue !== 'function') throw new TypeError('An assurance bundle store is required.');

  function createAssuranceBundle(tenantId, evidenceId, input = {}, context = {}) {
    if (!bundles.enabled) throw new EvidenceConflictError('Assurance bundle delivery is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid assurance bundle request is required.');
    const item = registry.get(tenantId, evidenceId);
    if (item.status !== 'active') throw new EvidenceConflictError('Only active evidence can be exported.', { evidenceId });
    const version = input.version === undefined || input.version === null ? item.currentVersion : positiveInteger(input.version, 'version');
    const metadata = item.versions.find((entry) => entry.version === version);
    if (!metadata) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version', version });
    const recipientId = safeIdentifier(input.recipientId, 'recipientId');
    if (input.confirmation !== `EXPORT ${item.evidenceId} V${version} TO ${recipientId}`) {
      throw new EvidenceValidationError(`confirmation must be exactly EXPORT ${item.evidenceId} V${version} TO ${recipientId}.`, { field: 'confirmation' });
    }
    const purpose = cleanText(input.purpose, 'purpose', 10, 500);
    const requestedBy = safeIdentifier(context.actor, 'actor');
    const content = registry.readContent(tenantId, item.evidenceId, { version });
    if (content.sha256 !== metadata.sha256 || content.sizeBytes !== metadata.sizeBytes) {
      throw new EvidenceIntegrityError('The assurance bundle content does not match immutable evidence metadata.', { evidenceId: item.evidenceId, version });
    }

    const verification = registry.verify(tenantId, item.evidenceId);
    const custodyEvents = registry.events(tenantId, { evidenceId: item.evidenceId, limit: 5000 });
    const screening = typeof registry.screeningReport === 'function'
      ? registry.screeningReport(tenantId, item.evidenceId, { version })
      : null;
    const externalScans = typeof registry.externalScanAttestations === 'function'
      ? registry.externalScanAttestations(tenantId, item.evidenceId, { version, limit: 5000 })
      : [];
    const preservationReceipts = typeof registry.evidencePreservationReceipts === 'function'
      ? registry.evidencePreservationReceipts(tenantId, item.evidenceId, { limit: 100_000 })
          .filter((receipt) => receipt.evidenceVersion === version)
      : [];
    const timeAttestations = preservationReceipts.flatMap((receipt) => (
      typeof registry.evidenceTimeAttestations === 'function'
        ? registry.evidenceTimeAttestations(tenantId, receipt.archiveId, { limit: 100_000 })
        : []
    ));
    const timeAttestationVerifications = preservationReceipts.map((receipt) => (
      typeof registry.effectiveArchiveVerification === 'function'
        ? registry.effectiveArchiveVerification(tenantId, receipt.archiveId)
        : { archiveId: receipt.archiveId, operationalQuorumSatisfied: null }
    ));
    const operationallyAcceptable = timeAttestationVerifications.every((entry) => entry.operationalQuorumSatisfied !== false);

    const sections = {
      item: redactItem(item),
      version: structuredClone(metadata),
      verification,
      custodyEvents,
      screening,
      externalScans,
      preservationReceipts,
      timeAttestations,
      timeAttestationVerifications,
      assurancePosture: {
        cryptographicallyVerified: Boolean(verification?.valid),
        operationallyAcceptable,
        governedArchives: timeAttestationVerifications.length,
        operationalQuorumArchives: timeAttestationVerifications.filter((entry) => entry.operationalQuorumSatisfied).length
      },
      content: {
        filename: content.filename,
        mediaType: content.mediaType,
        sha256: content.sha256,
        sizeBytes: content.sizeBytes,
        contentBase64: content.content.toString('base64')
      }
    };
    const sectionDigests = Object.fromEntries(Object.entries(sections).map(([name, value]) => [name, sha256(stableStringify(value))]));
    const manifest = {
      format: MANIFEST_FORMAT,
      version: 1,
      tenantId,
      evidenceId: item.evidenceId,
      evidenceVersion: version,
      contentSha256: metadata.sha256,
      recipientId,
      requestedBy,
      purpose,
      operationallyAcceptable,
      sectionDigests
    };
    manifest.bundleDigest = sha256(stableStringify(manifest));

    return bundles.queue({
      tenantId,
      evidenceId: item.evidenceId,
      evidenceVersion: version,
      contentSha256: metadata.sha256,
      recipientId,
      requestedBy,
      purpose,
      manifest,
      evidence: sections
    });
  }

  function assuranceBundles(tenantId, evidenceId = null, options = {}) {
    if (evidenceId) registry.get(tenantId, evidenceId);
    return bundles.list(tenantId, { evidenceId, ...options });
  }

  function claimAssuranceBundles(body, headers) { return bundles.claimSigned(body, headers); }
  function acknowledgeAssuranceBundle(bundleId, body, headers) { return bundles.acknowledgeSigned(bundleId, body, headers); }
  function assuranceBundleStatus(tenantId) { return bundles.tenantStatus(tenantId); }

  function health() {
    const base = registry.health();
    const delivery = bundles.health();
    const unavailable = bundles.required && delivery.status !== 'ready';
    return {
      ...base,
      required: Boolean(base.required || bundles.required),
      status: unavailable || base.status === 'unavailable' ? 'unavailable' : base.status,
      assuranceBundles: delivery
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const delivery = bundles.tenantStatus(tenantId);
      return {
        ...base,
        status: bundles.required && delivery.status !== 'ready' ? 'unavailable' : base.status,
        assuranceBundles: delivery
      };
    } catch (error) {
      return {
        ...base,
        status: bundles.required ? 'unavailable' : base.status,
        assuranceBundles: { status: 'unavailable', enabled: bundles.enabled, required: bundles.required, error: error?.code ?? 'assurance_bundle_store_unavailable' }
      };
    }
  }

  return Object.freeze({
    ...registry,
    health,
    tenantStatus,
    createAssuranceBundle,
    assuranceBundles,
    claimAssuranceBundles,
    acknowledgeAssuranceBundle,
    assuranceBundleStatus,
    assuranceBundleEnabled: bundles.enabled,
    assuranceBundleStore: bundles
  });
}

export function createEvidenceAssuranceBundleRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env);
  const bundles = createEvidenceAssuranceBundleStoreFromEnvironment({ env });
  return createEvidenceAssuranceBundleRegistry({ registry, bundles });
}

function redactItem(item) {
  const copy = structuredClone(item);
  if (copy.legalHold) {
    delete copy.legalHold.matterId;
    delete copy.legalHold.reason;
  }
  return copy;
}
function positiveInteger(value, field) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) throw new EvidenceValidationError(`${field} must be a positive integer.`, { field }); return parsed; }
function safeIdentifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, min, max) { const text = String(value ?? '').trim(); if (text.length < min || text.length > max) throw new EvidenceValidationError(`${field} must contain ${min} to ${max} characters.`, { field }); return text; }
function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
