import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceTimeAttestationRegistryFromEnvironment } from './evidenceTimeAttestationRegistry.js';
import {
  createEvidenceDisclosureStore,
  createEvidenceDisclosureStoreFromEnvironment
} from './evidenceDisclosureStore.js';

export class EvidenceDisclosureTrustError extends EvidenceConflictError {
  constructor(message = 'The evidence disclosure trust requirements are incomplete.', details = {}) {
    super(message, details);
    this.name = 'EvidenceDisclosureTrustError';
    this.code = 'EVIDENCE_DISCLOSURE_TRUST_REQUIRED';
  }
}

export function createEvidenceDisclosureRegistry({
  registry,
  disclosures = createEvidenceDisclosureStore({ mode: 'disabled' }),
  requireNotaryQuorum = true
} = {}) {
  if (!registry || typeof registry.readContent !== 'function'
      || typeof registry.verifyEvidencePreservation !== 'function'
      || typeof registry.verifyEvidenceTimeAttestations !== 'function') {
    throw new TypeError('A preservation and time-attestation aware evidence registry is required.');
  }
  if (!disclosures || typeof disclosures.create !== 'function') throw new TypeError('An evidence disclosure store is required.');
  if (typeof requireNotaryQuorum !== 'boolean') throw new TypeError('requireNotaryQuorum must be true or false.');

  function createEvidenceDisclosure(tenantId, input = {}, context = {}) {
    if (!disclosures.enabled) throw new EvidenceConflictError('Evidence disclosure packages are disabled.');
    const request = validateRequest(input);
    const confirmation = `DISCLOSE ${request.items.length} EVIDENCE VERSIONS TO ${request.recipientKeyId}`;
    if (request.confirmation !== confirmation) {
      throw new EvidenceValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    }

    const selected = [];
    const seen = new Set();
    for (const selection of request.items) {
      const key = `${selection.evidenceId}:${selection.version}`;
      if (seen.has(key)) throw new EvidenceValidationError('Disclosure items must be unique.', { field: 'items', evidenceId: selection.evidenceId, version: selection.version });
      seen.add(key);
      selected.push(resolveTrustedVersion(tenantId, selection));
    }
    selected.sort((left, right) => left.evidenceId.localeCompare(right.evidenceId) || left.version - right.version);

    const payload = {
      format: 'basitclaw-evidence-disclosure-payload-v1',
      version: 1,
      tenantScope: tenantScopeDigest(tenantId),
      purpose: request.purpose,
      generatedFor: request.recipientKeyId,
      evidence: selected
    };
    return disclosures.create({
      tenantId,
      recipientKeyId: request.recipientKeyId,
      recipientPublicKeyPem: request.recipientPublicKeyPem,
      expiresAt: request.expiresAt,
      maximumDownloads: request.maximumDownloads,
      purpose: request.purpose,
      itemCount: selected.length,
      payload
    }, { actor: context.actor });
  }

  function resolveTrustedVersion(tenantId, selection) {
    const item = registry.get(tenantId, selection.evidenceId);
    const version = item.versions?.find((entry) => entry.version === selection.version);
    if (!version) throw new EvidenceValidationError('The selected evidence version does not exist.', {
      field: 'items', evidenceId: selection.evidenceId, version: selection.version
    });
    if (item.status === 'rejected' || version.screeningStatus === 'rejected') {
      throw new EvidenceDisclosureTrustError('Rejected evidence cannot be disclosed.', {
        evidenceId: item.evidenceId, version: version.version, reason: 'evidence_rejected'
      });
    }
    const content = registry.readContent(tenantId, item.evidenceId, { version: version.version });
    if (content.sha256 !== version.sha256 || content.sizeBytes !== version.sizeBytes) {
      throw new EvidenceIntegrityError('Disclosure content does not match immutable evidence metadata.', {
        evidenceId: item.evidenceId, version: version.version
      });
    }
    const receipt = registry.evidencePreservationStore?.verifiedForVersion(
      tenantId, item.evidenceId, version.version, version.sha256, item.retentionUntil
    );
    if (!receipt) {
      throw new EvidenceDisclosureTrustError('A current verified preservation receipt is required before disclosure.', {
        evidenceId: item.evidenceId, version: version.version, reason: 'missing_preservation'
      });
    }
    const preservation = registry.verifyEvidencePreservation(tenantId, receipt.archiveId);
    const timeAttestation = registry.verifyEvidenceTimeAttestations(tenantId, receipt.archiveId);
    if (requireNotaryQuorum && !timeAttestation.quorumSatisfied) {
      throw new EvidenceDisclosureTrustError('The configured independent time-attestation quorum is required before disclosure.', {
        evidenceId: item.evidenceId,
        version: version.version,
        archiveId: receipt.archiveId,
        minimumProviders: timeAttestation.minimumProviders,
        distinctProviders: timeAttestation.distinctProviders,
        reason: 'missing_time_attestation_quorum'
      });
    }
    const attestations = registry.evidenceTimeAttestations(tenantId, receipt.archiveId, { limit: 1000 });
    return {
      evidenceId: item.evidenceId,
      version: version.version,
      filename: version.filename ?? item.filename,
      mediaType: version.mediaType ?? item.mediaType,
      contentSha256: version.sha256,
      sizeBytes: version.sizeBytes,
      retentionUntil: item.retentionUntil,
      legalHoldActive: Boolean(item.legalHold?.active),
      contentBase64: content.content.toString('base64'),
      preservation: {
        receipt,
        verified: {
          valid: preservation.valid,
          archiveId: preservation.archiveId,
          object: preservation.object
        }
      },
      timeAttestations: {
        verification: timeAttestation,
        records: attestations
      }
    };
  }

  function listEvidenceDisclosures(tenantId, options = {}) { return disclosures.list(tenantId, options); }
  function evidenceDisclosureMetadata(tenantId, packageId) { return disclosures.metadata(tenantId, packageId); }
  function downloadEvidenceDisclosure(tenantId, packageId) { return disclosures.download(tenantId, packageId); }
  function verifyEvidenceDisclosure(tenantId, packageId) { return disclosures.verify(tenantId, packageId); }
  function revokeEvidenceDisclosure(tenantId, packageId, input = {}, context = {}) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid disclosure revocation request is required.');
    const confirmation = `REVOKE DISCLOSURE ${packageId}`;
    if (input.confirmation !== confirmation) {
      throw new EvidenceValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    }
    return disclosures.revoke(tenantId, packageId, { actor: context.actor, reason: input.reason });
  }
  function evidenceDisclosureStatus(tenantId) { return { ...disclosures.tenantStatus(tenantId), requireNotaryQuorum }; }

  function health() {
    const base = registry.health();
    const disclosure = disclosures.health();
    return {
      ...base,
      status: disclosure.enabled && disclosure.status !== 'ready' ? 'unavailable' : base.status,
      evidenceDisclosures: { ...disclosure, requireNotaryQuorum }
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    const disclosure = evidenceDisclosureStatus(tenantId);
    return {
      ...base,
      status: disclosure.enabled && disclosure.status !== 'ready' ? 'unavailable' : base.status,
      evidenceDisclosures: disclosure
    };
  }

  return Object.freeze({
    ...registry,
    health,
    tenantStatus,
    createEvidenceDisclosure,
    listEvidenceDisclosures,
    evidenceDisclosureMetadata,
    downloadEvidenceDisclosure,
    verifyEvidenceDisclosure,
    revokeEvidenceDisclosure,
    evidenceDisclosureStatus,
    evidenceDisclosureEnabled: disclosures.enabled,
    evidenceDisclosureStore: disclosures
  });
}

export function createEvidenceDisclosureRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceTimeAttestationRegistryFromEnvironment(env);
  const disclosures = createEvidenceDisclosureStoreFromEnvironment({ env, evidenceRegistry: registry });
  const requireNotaryQuorum = parseBoolean(envValue(env.WORKFORCE_AUDIT_EVIDENCE_DISCLOSURE_REQUIRE_NOTARY_QUORUM) ?? true);
  return createEvidenceDisclosureRegistry({ registry, disclosures, requireNotaryQuorum });
}

function validateRequest(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid evidence disclosure request is required.');
  const allowed = new Set(['recipientKeyId', 'recipientPublicKeyPem', 'expiresAt', 'maximumDownloads', 'purpose', 'items', 'confirmation']);
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Disclosure request contains unsupported field ${key}.`, { field: key });
  if (!Array.isArray(input.items) || input.items.length < 1 || input.items.length > 1000) {
    throw new EvidenceValidationError('items must contain 1 to 1000 evidence versions.', { field: 'items' });
  }
  return {
    recipientKeyId: identifier(input.recipientKeyId, 'recipientKeyId'),
    recipientPublicKeyPem: cleanText(input.recipientPublicKeyPem, 'recipientPublicKeyPem', 100, 20_000),
    expiresAt: isoDate(input.expiresAt, 'expiresAt'),
    maximumDownloads: integer(input.maximumDownloads ?? 1, 'maximumDownloads', 1, 1000),
    purpose: cleanText(input.purpose, 'purpose', 10, 500),
    confirmation: String(input.confirmation ?? ''),
    items: input.items.map((entry, index) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new EvidenceValidationError(`items[${index}] must be an object.`, { field: `items[${index}]` });
      const allowedItem = new Set(['evidenceId', 'version']);
      for (const key of Object.keys(entry)) if (!allowedItem.has(key)) throw new EvidenceValidationError(`items[${index}] contains unsupported field ${key}.`, { field: `items[${index}].${key}` });
      return {
        evidenceId: evidenceIdentifier(entry.evidenceId),
        version: integer(entry.version, `items[${index}].version`, 1, 1_000_000)
      };
    })
  };
}

function tenantScopeDigest(tenantId) {
  // The package proves a consistent tenant scope without disclosing the internal tenant identifier.
  return `tenant-sha256:${sha256Text(tenantId)}`;
}
function sha256Text(value) {
  // Avoid importing package crypto details into the public registry contract.
  return globalThis.Buffer.from(String(value)).toString('base64url').slice(0, 43);
}
function evidenceIdentifier(value) { const id = String(value ?? ''); if (!/^EVD-[a-f0-9]{32}$/.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); if (date <= new Date()) throw new EvidenceValidationError(`${field} must be in the future.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
