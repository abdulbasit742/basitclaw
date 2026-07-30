import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationGovernanceRegistryFromEnvironment } from './evidenceTimeAttestationGovernanceRegistry.js';
import {
  createEvidenceDisclosurePackageStore,
  createEvidenceDisclosurePackageStoreFromEnvironment
} from './evidenceDisclosurePackageStore.js';

const MANIFEST_FORMAT = 'basitclaw-evidence-disclosure-manifest';

export function createEvidenceDisclosurePackageRegistry({
  registry,
  disclosures = createEvidenceDisclosurePackageStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.readContent !== 'function' || typeof registry.verify !== 'function'
      || typeof registry.effectiveArchiveVerification !== 'function') {
    throw new TypeError('A notary-governance-aware evidence registry is required.');
  }
  if (!disclosures || typeof disclosures.issue !== 'function') throw new TypeError('An evidence disclosure package store is required.');

  function generateEvidenceDisclosurePackage(tenantId, evidenceId, input = {}, context = {}) {
    if (!disclosures.enabled) throw new EvidenceConflictError('Evidence disclosure packages are disabled.');
    const request = normaliseRequest(input);
    const item = registry.get(tenantId, evidenceId);
    if (item.status !== 'active') throw new EvidenceConflictError('Only active evidence can be exported.', { evidenceId, status: item.status });
    if (request.confirmation !== `EXPORT ${item.evidenceId}`) {
      throw new EvidenceValidationError(`confirmation must be exactly EXPORT ${item.evidenceId}.`, { field: 'confirmation' });
    }
    const versions = request.versions ?? [item.currentVersion];
    const selected = versions.map((number) => {
      const metadata = item.versions.find((entry) => entry.version === number);
      if (!metadata) throw new EvidenceValidationError('A requested disclosure version does not exist.', { field: 'versions', version: number });
      return metadata;
    });
    const manifest = buildManifest(tenantId, item, selected);
    const contents = request.includeContent
      ? selected.map((metadata) => registry.readContent(tenantId, item.evidenceId, { version: metadata.version }))
      : [];
    return disclosures.issue({
      tenantId,
      evidenceId: item.evidenceId,
      versions: selected.map((entry) => entry.version),
      actor: context.actor,
      purpose: request.purpose,
      includeContent: request.includeContent,
      recipientId: request.recipientId,
      manifest,
      contents
    });
  }

  function evidenceDisclosureReceipts(tenantId, evidenceId, options = {}) {
    registry.get(tenantId, evidenceId);
    return disclosures.list(tenantId, { evidenceId, ...options });
  }

  function verifyEvidenceDisclosureReceipt(tenantId, packageId) {
    return disclosures.verifyReceipt(tenantId, packageId);
  }

  function evidenceDisclosureStatus(tenantId) {
    return disclosures.tenantStatus(tenantId);
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    const disclosure = disclosures.enabled
      ? disclosures.verifyTenant(tenantId)
      : { valid: true, enabled: false, checkedReceipts: 0 };
    return { ...base, disclosure };
  }

  function health() {
    const base = registry.health();
    const disclosure = disclosures.health();
    return {
      ...base,
      status: disclosure.enabled && disclosure.status !== 'ready'
        ? 'unavailable'
        : base.status,
      evidenceDisclosure: disclosure
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    const disclosure = disclosures.tenantStatus(tenantId);
    return {
      ...base,
      status: disclosure.enabled && disclosure.status === 'unavailable'
        ? 'unavailable'
        : base.status,
      evidenceDisclosure: disclosure
    };
  }

  function buildManifest(tenantId, item, selectedVersions) {
    const screenings = selectedVersions.map((version) => registry.screeningReport(tenantId, item.evidenceId, { version: version.version }));
    const externalScans = typeof registry.externalScanAttestations === 'function'
      ? selectedVersions.map((version) => ({
          version: version.version,
          attestations: registry.externalScanAttestations(tenantId, item.evidenceId, { version: version.version, limit: 5000 })
        }))
      : [];
    const allPreservations = typeof registry.evidencePreservationReceipts === 'function'
      ? registry.evidencePreservationReceipts(tenantId, item.evidenceId, { limit: 5000 })
      : [];
    const selectedNumbers = new Set(selectedVersions.map((entry) => entry.version));
    const preservations = allPreservations.filter((receipt) => selectedNumbers.has(receipt.evidenceVersion));
    const timeAttestationGovernance = preservations.map((receipt) => ({
      archiveId: receipt.archiveId,
      evidenceVersion: receipt.evidenceVersion,
      effectiveVerification: registry.effectiveArchiveVerification(tenantId, receipt.archiveId)
    }));
    const custody = registry.verify(tenantId, item.evidenceId);
    return {
      format: MANIFEST_FORMAT,
      version: 1,
      evidence: {
        evidenceId: item.evidenceId,
        filename: item.filename,
        mediaType: item.mediaType,
        description: item.description,
        sourceType: item.sourceType,
        sourceSystem: item.sourceSystem,
        collectedAt: item.collectedAt,
        ingestedAt: item.ingestedAt,
        retentionUntil: item.retentionUntil,
        status: item.status,
        currentVersion: item.currentVersion,
        selectedVersions: selectedVersions.map((entry) => structuredClone(entry)),
        legalHold: item.legalHold ? {
          active: Boolean(item.legalHold.active),
          placedAt: item.legalHold.placedAt,
          reviewAt: item.legalHold.reviewAt,
          releasedAt: item.legalHold.releasedAt
        } : null
      },
      trust: {
        custody,
        screeningReports: screenings,
        externalScanAttestations: externalScans,
        preservationReceipts: preservations,
        timeAttestationGovernance
      },
      disclosurePolicy: {
        metadataOnlyDefault: true,
        contentRequiresApprovedRecipient: true,
        arbitraryRecipientKeysAccepted: false,
        plaintextPackagePersisted: false,
        revokedOrSupersededAttestationsExcludedFromOperationalQuorum: true
      }
    };
  }

  return Object.freeze({
    ...registry,
    verify,
    health,
    tenantStatus,
    generateEvidenceDisclosurePackage,
    evidenceDisclosureReceipts,
    verifyEvidenceDisclosureReceipt,
    evidenceDisclosureStatus,
    evidenceDisclosureEnabled: disclosures.enabled,
    evidenceDisclosureStore: disclosures
  });
}

export function createEvidenceDisclosurePackageRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env);
  const disclosures = createEvidenceDisclosurePackageStoreFromEnvironment({ env });
  if (disclosures.enabled && !registry.enabled) throw new EvidenceConflictError('Evidence disclosure packages require enabled evidence custody.');
  return createEvidenceDisclosurePackageRegistry({ registry, disclosures });
}

function normaliseRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid disclosure package request is required.');
  const allowed = new Set(['versions', 'purpose', 'confirmation', 'includeContent', 'recipientId']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Disclosure request contains unsupported field ${key}.`, { field: key });
  const includeContent = input.includeContent === undefined ? false : booleanValue(input.includeContent, 'includeContent');
  if (includeContent && !String(input.recipientId ?? '').trim()) throw new EvidenceValidationError('recipientId is required when includeContent is true.', { field: 'recipientId' });
  if (!includeContent && input.recipientId !== undefined && input.recipientId !== null) throw new EvidenceValidationError('recipientId is allowed only for content-inclusive packages.', { field: 'recipientId' });
  return {
    versions: input.versions === undefined ? null : uniqueVersions(input.versions),
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    confirmation: String(input.confirmation ?? ''),
    includeContent,
    recipientId: includeContent ? safeIdentifier(input.recipientId, 'recipientId') : null
  };
}
function uniqueVersions(value) { if (!Array.isArray(value) || !value.length || value.length > 100) throw new EvidenceValidationError('versions must contain 1 to 100 version numbers.', { field: 'versions' }); return [...new Set(value.map((entry) => positiveInteger(entry, 'version')))].sort((a, b) => a - b); }
function positiveInteger(value, field) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) throw new EvidenceValidationError(`${field} must be a positive integer.`, { field }); return parsed; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new EvidenceValidationError(`${field} must be true or false.`, { field }); return value; }
function safeIdentifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
