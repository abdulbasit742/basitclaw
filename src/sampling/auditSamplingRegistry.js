import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from '../evidence/evidenceRegistry.js';
import { createEvidenceAssuranceBundleRegistryFromEnvironment } from '../evidence/evidenceAssuranceBundleRegistry.js';
import { createAuditSamplingStore, createAuditSamplingStoreFromEnvironment } from './auditSamplingStore.js';

export function createAuditSamplingRegistry({
  registry,
  sampling = createAuditSamplingStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.get !== 'function' || typeof registry.verify !== 'function') {
    throw new TypeError('An evidence-aware registry is required for audit sampling.');
  }
  if (!sampling || typeof sampling.create !== 'function') throw new TypeError('An audit sampling store is required.');

  function createSamplingPlan(tenantId, input = {}, context = {}) {
    if (!sampling.enabled) throw new EvidenceConflictError('Audit sampling is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('An audit sampling request is required.');
    const evidenceId = String(input.evidenceId ?? '');
    const item = registry.get(tenantId, evidenceId);
    const evidenceVersion = positiveInteger(input.evidenceVersion ?? item.currentVersion, 'evidenceVersion');
    const version = item.versions?.find((entry) => entry.version === evidenceVersion);
    if (!version) throw new EvidenceValidationError('The sampling population evidence version does not exist.', { field: 'evidenceVersion', evidenceVersion });
    if (item.status === 'disposed' || item.status === 'rejected') {
      throw new EvidenceConflictError('Disposed or rejected evidence cannot support an audit sampling plan.', { evidenceId: item.evidenceId, status: item.status });
    }
    assertEvidenceAccessible(tenantId, item.evidenceId, evidenceVersion);
    return sampling.create({
      tenantId,
      engagementId: input.engagementId,
      objective: input.objective,
      rationale: input.rationale,
      evidenceId: item.evidenceId,
      evidenceVersion,
      evidenceContentSha256: version.sha256,
      idempotencyKey: input.idempotencyKey,
      method: input.method,
      sampleSize: input.sampleSize,
      strata: input.strata,
      population: input.population
    }, { actor: context.actor });
  }

  function approveSamplingPlan(tenantId, planId, input, context = {}) {
    const plan = sampling.get(tenantId, planId);
    revalidateEvidenceBinding(tenantId, plan);
    return sampling.approve(tenantId, planId, input, context);
  }

  function cancelSamplingPlan(tenantId, planId, input, context = {}) {
    return sampling.cancel(tenantId, planId, input, context);
  }

  function samplingPlan(tenantId, planId) {
    const plan = sampling.get(tenantId, planId);
    return { ...plan, evidenceBindingCurrent: evidenceBindingCurrent(tenantId, plan) };
  }

  function samplingPlans(tenantId, options = {}) {
    return sampling.list(tenantId, options).map((plan) => ({
      ...plan,
      evidenceBindingCurrent: evidenceBindingCurrent(tenantId, plan)
    }));
  }

  function verifySamplingPlan(tenantId, planId) {
    const plan = sampling.get(tenantId, planId);
    const storeVerification = sampling.verify(tenantId, planId);
    revalidateEvidenceBinding(tenantId, plan);
    return { ...storeVerification, evidenceBindingValid: true };
  }

  function auditSamplingStatus(tenantId) {
    const base = sampling.status(tenantId);
    if (!sampling.enabled) return base;
    const plans = sampling.list(tenantId, { limit: 5000 });
    let staleEvidenceBindings = 0;
    for (const plan of plans) if (!evidenceBindingCurrent(tenantId, plan)) staleEvidenceBindings += 1;
    return {
      ...base,
      staleEvidenceBindings,
      assuranceReady: staleEvidenceBindings === 0,
      statisticalValidityAsserted: false
    };
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    if (!sampling.enabled) return { ...base, auditSampling: { valid: true, enabled: false } };
    if (evidenceId) {
      const plans = sampling.list(tenantId, { limit: 5000 }).filter((plan) => plan.evidenceId === evidenceId);
      for (const plan of plans) verifySamplingPlan(tenantId, plan.planId);
      return { ...base, auditSampling: { valid: true, enabled: true, checkedPlans: plans.length } };
    }
    return { ...base, auditSampling: sampling.verifyTenant(tenantId) };
  }

  function health() {
    const base = registry.health();
    const sampleHealth = sampling.health();
    return {
      ...base,
      status: base.status === 'unavailable' || (sampling.enabled && sampleHealth.status !== 'ready') ? 'unavailable' : base.status,
      auditSampling: sampleHealth
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const sampleStatus = auditSamplingStatus(tenantId);
      return {
        ...base,
        status: base.status === 'unavailable' || (sampling.enabled && sampleStatus.status !== 'ready')
          ? 'unavailable'
          : sampleStatus.staleEvidenceBindings ? 'attention' : base.status,
        auditSampling: sampleStatus
      };
    } catch (error) {
      return {
        ...base,
        status: sampling.enabled ? 'unavailable' : base.status,
        auditSampling: { status: 'unavailable', enabled: sampling.enabled, error: error?.code ?? 'audit_sampling_store_unavailable' }
      };
    }
  }

  function assertEvidenceAccessible(tenantId, evidenceId, version) {
    if (typeof registry.assertVersionAccessible === 'function') {
      registry.assertVersionAccessible(tenantId, evidenceId, version);
      return;
    }
    if (typeof registry.screeningReport === 'function') {
      const report = registry.screeningReport(tenantId, evidenceId, { version });
      const status = report?.status ?? report?.decision;
      if (['quarantined', 'rejected', 'blocked'].includes(status)) {
        throw new EvidenceConflictError('Quarantined or rejected evidence cannot support an audit sampling plan.', { evidenceId, version, status });
      }
    }
  }

  function evidenceBindingCurrent(tenantId, plan) {
    try {
      const item = registry.get(tenantId, plan.evidenceId);
      const version = item.versions?.find((entry) => entry.version === plan.evidenceVersion);
      return Boolean(version && version.sha256 === plan.evidenceContentSha256 && item.status !== 'disposed' && item.status !== 'rejected');
    } catch {
      return false;
    }
  }

  function revalidateEvidenceBinding(tenantId, plan) {
    const item = registry.get(tenantId, plan.evidenceId);
    const version = item.versions?.find((entry) => entry.version === plan.evidenceVersion);
    if (!version || version.sha256 !== plan.evidenceContentSha256) {
      throw new EvidenceIntegrityError('The audit sampling population evidence binding is no longer valid.', {
        planId: plan.planId,
        evidenceId: plan.evidenceId,
        evidenceVersion: plan.evidenceVersion
      });
    }
    if (item.status === 'disposed' || item.status === 'rejected') {
      throw new EvidenceConflictError('The audit sampling population evidence is no longer available.', { planId: plan.planId, status: item.status });
    }
    assertEvidenceAccessible(tenantId, plan.evidenceId, plan.evidenceVersion);
  }

  return Object.freeze({
    ...registry,
    verify,
    health,
    tenantStatus,
    createSamplingPlan,
    approveSamplingPlan,
    cancelSamplingPlan,
    samplingPlan,
    samplingPlans,
    verifySamplingPlan,
    auditSamplingStatus,
    auditSamplingEnabled: sampling.enabled,
    auditSamplingStore: sampling
  });
}

export function createAuditSamplingRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceAssuranceBundleRegistryFromEnvironment(env);
  const sampling = createAuditSamplingStoreFromEnvironment({ env });
  if (sampling.enabled && !registry.enabled) throw new TypeError('Audit sampling requires enabled evidence custody.');
  return createAuditSamplingRegistry({ registry, sampling });
}

function positiveInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) throw new EvidenceValidationError(`${field} must be a positive integer.`, { field });
  return parsed;
}
