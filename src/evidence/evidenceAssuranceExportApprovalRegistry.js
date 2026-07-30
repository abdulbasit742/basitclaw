import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceAssuranceBundleRegistryFromEnvironment } from './evidenceAssuranceBundleRegistry.js';
import {
  createEvidenceAssuranceExportApprovalStore,
  createEvidenceAssuranceExportApprovalStoreFromEnvironment
} from './evidenceAssuranceExportApprovalStore.js';

export function createEvidenceAssuranceExportApprovalRegistry({
  registry,
  approvals = createEvidenceAssuranceExportApprovalStore({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.createAssuranceBundle !== 'function') throw new TypeError('An assurance-bundle-aware evidence registry is required.');
  if (!approvals || typeof approvals.request !== 'function') throw new TypeError('An assurance export approval store is required.');
  const directCreateAssuranceBundle = registry.createAssuranceBundle.bind(registry);

  function requestAssuranceExport(tenantId, evidenceId, input = {}, context = {}) {
    if (!approvals.enabled) throw new EvidenceConflictError('Assurance export approval is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid assurance export request is required.');
    const item = registry.get(tenantId, evidenceId);
    if (item.status !== 'active') throw new EvidenceConflictError('Only active evidence can be requested for export.', { evidenceId });
    const version = input.version === undefined || input.version === null ? item.currentVersion : positiveInteger(input.version, 'version');
    const metadata = item.versions.find((entry) => entry.version === version);
    if (!metadata) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version', version });
    const recipientId = identifier(input.recipientId, 'recipientId');
    const configuredRecipients = registry.assuranceBundleStore?.recipientIds?.() ?? [];
    if (!configuredRecipients.includes(recipientId)) throw new EvidenceValidationError('The requested assurance recipient is not configured.', { field: 'recipientId' });
    const purpose = cleanText(input.purpose, 'purpose', 10, 500);
    if (input.confirmation !== `REQUEST EXPORT ${item.evidenceId} V${version} TO ${recipientId}`) {
      throw new EvidenceValidationError(`confirmation must be exactly REQUEST EXPORT ${item.evidenceId} V${version} TO ${recipientId}.`, { field: 'confirmation' });
    }
    const content = registry.readContent(tenantId, item.evidenceId, { version });
    if (content.sha256 !== metadata.sha256 || content.sizeBytes !== metadata.sizeBytes) {
      throw new EvidenceIntegrityError('The export request does not match immutable evidence metadata.', { evidenceId: item.evidenceId, version });
    }
    return approvals.request({
      tenantId,
      evidenceId: item.evidenceId,
      evidenceVersion: version,
      contentSha256: metadata.sha256,
      recipientId,
      purpose
    }, context);
  }

  function createAssuranceBundle(tenantId, evidenceId, input = {}, context = {}) {
    if (!approvals.enabled) return directCreateAssuranceBundle(tenantId, evidenceId, input, context);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid approved assurance export request is required.');
    const requestId = identifier(input.approvalRequestId, 'approvalRequestId');
    if (input.confirmation !== `MATERIALIZE EXPORT ${requestId}`) {
      throw new EvidenceValidationError(`confirmation must be exactly MATERIALIZE EXPORT ${requestId}.`, { field: 'confirmation' });
    }
    const approval = approvals.get(tenantId, requestId);
    if (approval.evidenceId !== evidenceId) throw new EvidenceValidationError('The approved request belongs to a different evidence item.', { field: 'approvalRequestId' });
    return approvals.executeApproved(tenantId, requestId, {
      evidenceId: approval.evidenceId,
      evidenceVersion: approval.evidenceVersion,
      contentSha256: approval.contentSha256,
      recipientId: approval.recipientId,
      purpose: approval.purpose
    }, context, () => directCreateAssuranceBundle(tenantId, approval.evidenceId, {
      version: approval.evidenceVersion,
      recipientId: approval.recipientId,
      purpose: approval.purpose,
      confirmation: `EXPORT ${approval.evidenceId} V${approval.evidenceVersion} TO ${approval.recipientId}`
    }, { actor: approval.requestedBy }));
  }

  function approveAssuranceExport(tenantId, requestId, context = {}) { return approvals.approve(tenantId, requestId, context); }
  function rejectAssuranceExport(tenantId, requestId, reason, context = {}) { return approvals.reject(tenantId, requestId, reason, context); }
  function cancelAssuranceExport(tenantId, requestId, context = {}) { return approvals.cancel(tenantId, requestId, context); }
  function assuranceExportApproval(tenantId, requestId) { return approvals.get(tenantId, requestId); }
  function assuranceExportApprovals(tenantId, options = {}) { return approvals.list(tenantId, options); }
  function assuranceExportApprovalStatus(tenantId) { return approvals.status(tenantId); }

  function health() {
    const base = registry.health();
    const approval = approvals.health();
    const unavailable = approvals.required && approval.status !== 'ready';
    return {
      ...base,
      required: Boolean(base.required || approvals.required),
      status: unavailable || base.status === 'unavailable' ? 'unavailable' : base.status,
      assuranceExportApprovals: approval
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const approval = approvals.status(tenantId);
      return {
        ...base,
        status: approvals.required && approval.status !== 'ready' ? 'unavailable' : base.status,
        assuranceExportApprovals: approval
      };
    } catch (error) {
      return {
        ...base,
        status: approvals.required ? 'unavailable' : base.status,
        assuranceExportApprovals: { status: 'unavailable', enabled: approvals.enabled, required: approvals.required, error: error?.code ?? 'assurance_export_approval_store_unavailable' }
      };
    }
  }

  return Object.freeze({
    ...registry,
    health,
    tenantStatus,
    createAssuranceBundle,
    requestAssuranceExport,
    approveAssuranceExport,
    rejectAssuranceExport,
    cancelAssuranceExport,
    assuranceExportApproval,
    assuranceExportApprovals,
    assuranceExportApprovalStatus,
    assuranceExportApprovalEnabled: approvals.enabled,
    assuranceExportApprovalStore: approvals
  });
}

export function createEvidenceAssuranceExportApprovalRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceAssuranceBundleRegistryFromEnvironment(env);
  const approvals = createEvidenceAssuranceExportApprovalStoreFromEnvironment({ env });
  return createEvidenceAssuranceExportApprovalRegistry({ registry, approvals });
}

function positiveInteger(value, field) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) throw new EvidenceValidationError(`${field} must be a positive integer.`, { field }); return parsed; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function cleanText(value, field, min, max) { const text = String(value ?? '').trim(); if (text.length < min || text.length > max) throw new EvidenceValidationError(`${field} must contain ${min} to ${max} characters.`, { field }); return text; }
