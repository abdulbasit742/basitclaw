import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceAssuranceBundleRegistryFromEnvironment } from './evidenceAssuranceBundleRegistry.js';
import {
  createEvidenceAssuranceGovernanceStore,
  createEvidenceAssuranceGovernanceStoreFromEnvironment
} from './evidenceAssuranceGovernanceStore.js';

export class EvidenceAssuranceGovernanceRequiredError extends EvidenceConflictError {
  constructor(message = 'Assurance bundle creation requires an approved governance request.', details = {}) {
    super(message, details);
    this.name = 'EvidenceAssuranceGovernanceRequiredError';
    this.code = 'EVIDENCE_ASSURANCE_GOVERNANCE_REQUIRED';
  }
}

export function createEvidenceAssuranceGovernanceRegistry({
  registry,
  governance = createEvidenceAssuranceGovernanceStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.createAssuranceBundle !== 'function'
      || typeof registry.claimAssuranceBundles !== 'function') {
    throw new TypeError('An assurance-bundle-aware evidence registry is required.');
  }
  if (!governance || typeof governance.request !== 'function') {
    throw new TypeError('An assurance governance store is required.');
  }
  const createBaseBundle = registry.createAssuranceBundle.bind(registry);
  const claimBaseBundles = registry.claimAssuranceBundles.bind(registry);
  const acknowledgeBaseBundle = registry.acknowledgeAssuranceBundle.bind(registry);

  function requestAssuranceBundle(tenantId, evidenceId, input = {}, context = {}) {
    if (!governance.enabled) return createBaseBundle(tenantId, evidenceId, input, context);
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid assurance governance request is required.');
    }
    const item = registry.get(tenantId, evidenceId);
    if (item.status !== 'active') throw new EvidenceConflictError('Only active evidence can be exported.', { evidenceId });
    const version = input.version === undefined || input.version === null
      ? item.currentVersion
      : positiveInteger(input.version, 'version');
    const metadata = item.versions.find((entry) => entry.version === version);
    if (!metadata) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version', version });
    const recipientId = safeIdentifier(input.recipientId, 'recipientId');
    if (input.confirmation !== `REQUEST EXPORT ${item.evidenceId} V${version} TO ${recipientId}`) {
      throw new EvidenceValidationError(
        `confirmation must be exactly REQUEST EXPORT ${item.evidenceId} V${version} TO ${recipientId}.`,
        { field: 'confirmation' }
      );
    }
    return governance.request({
      tenantId,
      evidenceId: item.evidenceId,
      evidenceVersion: version,
      contentSha256: metadata.sha256,
      recipientId,
      purpose: input.purpose,
      purposeCode: input.purposeCode,
      legalBasis: input.legalBasis,
      residencyZone: input.residencyZone
    }, {
      actor: context.actor,
      role: context.role
    });
  }

  function approveAssuranceRequest(tenantId, requestId, context = {}) {
    const approved = governance.approve(tenantId, requestId, {
      actor: context.actor,
      role: context.role
    });
    if (!approved.readyToSeal) return { request: approved, bundle: null };
    return sealApprovedRequest(tenantId, requestId);
  }

  function sealApprovedRequest(tenantId, requestId) {
    const request = governance.get(tenantId, requestId);
    if (request.state === 'sealed') {
      const existing = registry.assuranceBundles(tenantId, request.evidenceId, { limit: 5000 })
        .find((bundle) => bundle.bundleId === request.bundleId) ?? null;
      return { request, bundle: existing };
    }
    if (!request.readyToSeal) {
      throw new EvidenceAssuranceGovernanceRequiredError(
        'The assurance request has not reached approval quorum.',
        { requestId, state: request.state }
      );
    }
    const queued = createBaseBundle(tenantId, request.evidenceId, {
      version: request.evidenceVersion,
      recipientId: request.recipientId,
      purpose: request.purpose,
      confirmation: `EXPORT ${request.evidenceId} V${request.evidenceVersion} TO ${request.recipientId}`,
      governanceRequestId: request.requestId,
      purposeCode: request.purposeCode,
      legalBasis: request.legalBasis,
      residencyZone: request.residencyZone
    }, { actor: request.requestedBy });
    const attached = governance.attachBundle(tenantId, requestId, {
      bundleId: queued.bundle.bundleId,
      packageSha256: queued.bundle.packageSha256
    });
    return { request: attached, bundle: queued.bundle, duplicate: queued.duplicate, resealed: queued.resealed };
  }

  function rejectAssuranceRequest(tenantId, requestId, input = {}, context = {}) {
    return governance.reject(tenantId, requestId, { actor: context.actor, reason: input.reason });
  }

  function revokeAssuranceRequest(tenantId, requestId, input = {}, context = {}) {
    const request = governance.get(tenantId, requestId);
    if (request.bundleId) {
      const bundle = registry.assuranceBundles(tenantId, request.evidenceId, { limit: 5000 })
        .find((entry) => entry.bundleId === request.bundleId);
      if (bundle?.state === 'claimed' || bundle?.state === 'delivered') {
        throw new EvidenceConflictError(
          'A claimed or delivered assurance bundle cannot be revoked as though it had not left custody.',
          { requestId, bundleId: request.bundleId, bundleState: bundle.state }
        );
      }
    }
    return governance.revoke(tenantId, requestId, { actor: context.actor, reason: input.reason });
  }

  function assuranceRequests(tenantId, evidenceId = null, options = {}) {
    if (evidenceId) registry.get(tenantId, evidenceId);
    return governance.list(tenantId, { evidenceId, ...options });
  }
  function assuranceRequest(tenantId, requestId) { return governance.get(tenantId, requestId); }
  function assuranceGovernanceReport(tenantId) { return governance.report(tenantId); }
  function assuranceGovernanceStatus(tenantId) {
    const health = governance.health();
    const report = governance.enabled ? governance.report(tenantId) : governance.report();
    return { ...health, ...report };
  }

  function claimAssuranceBundles(body, headers) {
    const claimed = claimBaseBundles(body, headers);
    if (!governance.enabled) return claimed;
    const allowed = [];
    for (const bundle of claimed.bundles ?? claimed.jobs ?? []) {
      if (governance.deliveryAllowed(bundle.bundleId)) allowed.push(bundle);
      else governance.recordSuppressedDelivery(bundle.bundleId, claimed.recipientId);
    }
    return { ...claimed, bundles: allowed, jobs: allowed };
  }

  function acknowledgeAssuranceBundle(bundleId, body, headers) {
    if (governance.enabled && !governance.deliveryAllowed(bundleId)) {
      governance.recordSuppressedDelivery(bundleId, 'recipient');
      throw new EvidenceAssuranceGovernanceRequiredError(
        'The assurance bundle is no longer authorised for delivery.',
        { bundleId }
      );
    }
    const delivered = acknowledgeBaseBundle(bundleId, body, headers);
    if (governance.enabled) governance.markDelivered(bundleId, delivered.recipientId);
    return delivered;
  }

  function createAssuranceBundle(tenantId, evidenceId, input = {}, context = {}) {
    if (!governance.enabled) return createBaseBundle(tenantId, evidenceId, input, context);
    throw new EvidenceAssuranceGovernanceRequiredError(undefined, { evidenceId });
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    return governance.enabled
      ? { ...base, assuranceGovernance: governance.verifyTenant(tenantId) }
      : { ...base, assuranceGovernance: { valid: true, enabled: false } };
  }

  function health() {
    const base = registry.health();
    const policy = governance.health();
    const unavailable = governance.required && policy.status !== 'ready';
    return {
      ...base,
      required: Boolean(base.required || governance.required),
      status: unavailable || base.status === 'unavailable' ? 'unavailable' : base.status,
      assuranceGovernance: policy
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const report = governance.report(tenantId);
      const attention = (report.byState.pending ?? 0) > 0
        || (report.byState.approved ?? 0) > 0
        || (report.byState.revoked ?? 0) > 0
        || (report.byState.expired ?? 0) > 0;
      return {
        ...base,
        status: governance.required && governance.health().status !== 'ready'
          ? 'unavailable'
          : base.status === 'unavailable'
            ? 'unavailable'
            : attention ? 'attention' : base.status,
        assuranceGovernance: { status: 'ready', enabled: governance.enabled, ...report }
      };
    } catch (error) {
      return {
        ...base,
        status: governance.required ? 'unavailable' : base.status,
        assuranceGovernance: {
          status: 'unavailable',
          enabled: governance.enabled,
          required: governance.required,
          error: error?.code ?? 'assurance_governance_store_unavailable'
        }
      };
    }
  }

  return Object.freeze({
    ...registry,
    createAssuranceBundle,
    claimAssuranceBundles,
    acknowledgeAssuranceBundle,
    verify,
    health,
    tenantStatus,
    requestAssuranceBundle,
    approveAssuranceRequest,
    sealApprovedRequest,
    rejectAssuranceRequest,
    revokeAssuranceRequest,
    assuranceRequests,
    assuranceRequest,
    assuranceGovernanceReport,
    assuranceGovernanceStatus,
    assuranceGovernanceEnabled: governance.enabled,
    assuranceGovernanceStore: governance
  });
}

export function createEvidenceAssuranceGovernanceRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceAssuranceBundleRegistryFromEnvironment(env);
  const governance = createEvidenceAssuranceGovernanceStoreFromEnvironment({ env });
  if (governance.enabled && !registry.assuranceBundleEnabled) {
    throw new TypeError('Assurance governance requires enabled assurance bundle delivery.');
  }
  return createEvidenceAssuranceGovernanceRegistry({ registry, governance });
}

function positiveInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) {
    throw new EvidenceValidationError(`${field} must be a positive integer.`, { field });
  }
  return parsed;
}
function safeIdentifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) {
    throw new EvidenceValidationError(`${field} is invalid.`, { field });
  }
  return text;
}
