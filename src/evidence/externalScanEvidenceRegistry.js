import { resolve } from 'node:path';
import { createFileMutex } from '../security/fileMutex.js';
import { EvidenceConflictError, EvidenceIntegrityError, EvidenceValidationError } from './evidenceRegistry.js';
import { createScreenedEvidenceRegistryFromEnvironment } from './evidenceScreeningRegistry.js';
import {
  ExternalScanRequiredError,
  createExternalScanAttestationRegistryFromEnvironment
} from './externalScanAttestationRegistry.js';
import { createExternalScanContentReaderFromEnvironment } from './externalScanContentReader.js';
import { createExternalScanJobOutbox, createExternalScanJobOutboxFromEnvironment } from './externalScanJobOutbox.js';

const POLICY_RESOURCE = 'external-scan-release-policy';

export function createExternalScanEvidenceRegistry({
  registry,
  attestations,
  jobs = createExternalScanJobOutbox({ mode: 'disabled' }),
  contentReader = null,
  policyMutex = null
} = {}) {
  if (!registry || typeof registry.screeningReport !== 'function') throw new TypeError('A screened evidence registry is required.');
  if (!attestations || typeof attestations.list !== 'function') throw new TypeError('An external scan attestation registry is required.');
  if (!jobs || typeof jobs.list !== 'function') throw new TypeError('An external scan job outbox is required.');
  if (jobs.enabled && (!contentReader || typeof contentReader.read !== 'function')) throw new TypeError('A verified evidence content reader is required for enabled scanner delivery.');
  const policyLock = policyMutex ?? createPolicyMutex(registry, attestations.enabled || jobs.enabled);

  function recordExternalScanAttestation(bodyBuffer, headers) {
    return policyLock.withLock(POLICY_RESOURCE, () => {
      let authenticatedTenantId = null;
      const result = attestations.acceptSigned(bodyBuffer, headers, (attestation) => {
        authenticatedTenantId = attestation.tenantId;
        const report = registry.screeningReport(attestation.tenantId, attestation.evidenceId, { version: attestation.version });
        return { version: report.version, contentSha256: report.contentSha256 };
      });
      const jobCompletion = jobs.completeFromAttestation({ ...result.attestation, tenantId: authenticatedTenantId });
      return { ...result, jobCompletion };
    });
  }

  function externalScanAttestations(tenantId, evidenceId, options = {}) {
    return attestations.list(tenantId, { evidenceId, ...options });
  }

  function externalScanStatus(tenantId) {
    return attestations.tenantStatus(tenantId);
  }

  function queueExternalScanJob(tenantId, evidenceId, input = {}, context = {}) {
    if (!jobs.enabled) throw new EvidenceConflictError('External scan job delivery is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('A valid external scan job request is required.');
    return policyLock.withLock(POLICY_RESOURCE, () => {
      const item = registry.get(tenantId, evidenceId);
      const version = input.version === undefined || input.version === null ? item.currentVersion : positiveInteger(input.version, 'version');
      const report = registry.screeningReport(tenantId, evidenceId, { version });
      if (report.accessDecision !== 'quarantine') {
        throw new EvidenceConflictError('Only quarantined evidence versions can be queued for external scanning.', {
          evidenceId,
          version,
          accessDecision: report.accessDecision
        });
      }
      const content = contentReader.read(tenantId, evidenceId, { version });
      if (content.contentSha256 !== report.contentSha256 || content.sizeBytes !== report.sizeBytes) {
        throw new EvidenceIntegrityError('Scanner delivery content does not match the screening report.', { evidenceId, version });
      }
      return jobs.queue(content, input.providerId, context);
    });
  }

  function externalScanJobs(tenantId, evidenceId, options = {}) {
    return jobs.list(tenantId, { evidenceId, ...options });
  }

  function externalScanJobStatus(tenantId) {
    return jobs.tenantStatus(tenantId);
  }

  function claimExternalScanJobs(bodyBuffer, headers) {
    return jobs.claimSigned(bodyBuffer, headers);
  }

  function acknowledgeExternalScanJob(jobId, bodyBuffer, headers) {
    return jobs.acknowledgeSigned(jobId, bodyBuffer, headers);
  }

  function failExternalScanJob(jobId, bodyBuffer, headers) {
    return jobs.failSigned(jobId, bodyBuffer, headers);
  }

  function releaseQuarantine(tenantId, evidenceId, input, context = {}) {
    return policyLock.withLock(POLICY_RESOURCE, () => {
      const item = registry.get(tenantId, evidenceId);
      const report = registry.screeningReport(tenantId, evidenceId, { version: item.currentVersion });
      const latest = attestations.latest(tenantId, evidenceId, item.currentVersion);
      if (attestations.enabled && attestations.mode === 'enforce' && latest && latest.verdict !== 'clean') {
        throw new ExternalScanRequiredError(evidenceId, {
          version: item.currentVersion,
          reason: 'external_verdict_not_clean',
          latestVerdict: latest.verdict,
          providerId: latest.providerId,
          scannedAt: latest.scannedAt
        });
      }
      attestations.requireCleanForRelease(tenantId, evidenceId, item.currentVersion, report.contentSha256);
      return withExternalScan(tenantId, registry.releaseQuarantine(tenantId, evidenceId, input, context));
    });
  }

  function get(tenantId, evidenceId) {
    return withExternalScan(tenantId, registry.get(tenantId, evidenceId));
  }

  function list(tenantId, options = {}) {
    return registry.list(tenantId, options).map((item) => withExternalScan(tenantId, item));
  }

  function screeningReport(tenantId, evidenceId, options = {}) {
    const report = registry.screeningReport(tenantId, evidenceId, options);
    return {
      ...report,
      externalScan: attestations.latest(tenantId, evidenceId, report.version),
      externalScanJob: jobs.latest(tenantId, evidenceId, report.version)
    };
  }

  function verify(tenantId, evidenceId = null) {
    const result = registry.verify(tenantId, evidenceId);
    return { ...result, externalScan: attestations.verify(tenantId), externalScanJobs: jobs.verify(tenantId) };
  }

  function health() {
    const base = registry.health();
    const externalScan = attestations.health();
    const delivery = jobs.health();
    const policy = policyLock.health();
    const enforced = externalScan.mode === 'enforce';
    const unavailable = (enforced && externalScan.status !== 'ready')
      || (jobs.required && delivery.status !== 'ready')
      || ((attestations.enabled || jobs.enabled) && policy.status !== 'ready');
    return {
      ...base,
      required: Boolean(base.required || enforced || externalScan.requiredForRelease || jobs.required),
      status: unavailable ? 'unavailable' : base.status,
      externalScan: { ...externalScan, policyMutex: policy },
      externalScanDelivery: delivery
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const externalScan = attestations.tenantStatus(tenantId);
      const delivery = jobs.tenantStatus(tenantId);
      const unavailable = (externalScan.mode === 'enforce' && externalScan.status === 'unavailable')
        || (jobs.required && (delivery.status === 'unavailable' || delivery.deadLetters > 0));
      const attention = externalScan.status === 'attention' || delivery.status === 'attention';
      return {
        ...base,
        status: unavailable ? 'unavailable' : base.status === 'unavailable' ? 'unavailable' : attention ? 'attention' : base.status,
        externalScan,
        externalScanDelivery: delivery
      };
    } catch (error) {
      const enforced = attestations.mode === 'enforce' || attestations.requiredForRelease || jobs.required;
      return {
        ...base,
        status: enforced ? 'unavailable' : base.status,
        externalScan: { status: 'unavailable', mode: attestations.mode, requiredForRelease: attestations.requiredForRelease, error: error?.code ?? 'external_scan_store_unavailable' },
        externalScanDelivery: { status: 'unavailable', mode: jobs.mode, required: jobs.required, error: error?.code ?? 'external_scan_job_store_unavailable' }
      };
    }
  }

  function withExternalScan(tenantId, item) {
    if (!item || item.status === 'disposed') return item;
    const latest = attestations.latest(tenantId, item.evidenceId, item.currentVersion);
    const latestJob = jobs.latest(tenantId, item.evidenceId, item.currentVersion);
    return { ...item, externalScan: latest, externalScanJob: latestJob };
  }

  return Object.freeze({
    ...registry,
    get,
    list,
    screeningReport,
    releaseQuarantine,
    verify,
    health,
    tenantStatus,
    recordExternalScanAttestation,
    externalScanAttestations,
    externalScanStatus,
    queueExternalScanJob,
    externalScanJobs,
    externalScanJobStatus,
    claimExternalScanJobs,
    acknowledgeExternalScanJob,
    failExternalScanJob,
    externalScanEnabled: attestations.enabled,
    externalScanDeliveryEnabled: jobs.enabled,
    externalScanJobOutbox: jobs
  });
}

export function createExternalScanEvidenceRegistryFromEnvironment(env = process.env) {
  const registry = createScreenedEvidenceRegistryFromEnvironment(env);
  const attestations = createExternalScanAttestationRegistryFromEnvironment({ env, evidenceRegistry: registry });
  const jobs = createExternalScanJobOutboxFromEnvironment({ env, evidenceRegistry: registry });
  if (!registry.enabled && (attestations.enabled || jobs.enabled)) throw new EvidenceConflictError('External scanner controls require enabled evidence custody.');
  if (jobs.enabled && !registry.screeningEnabled) throw new EvidenceConflictError('External scan delivery requires enabled evidence screening.');
  if (jobs.enabled && !attestations.enabled) throw new EvidenceConflictError('External scan delivery requires signed external scanner attestations.');
  const contentReader = jobs.enabled ? createExternalScanContentReaderFromEnvironment({ env, evidenceRegistry: registry }) : null;
  return createExternalScanEvidenceRegistry({ registry, attestations, jobs, contentReader });
}

function createPolicyMutex(registry, scannerEnabled) {
  if (!scannerEnabled || !registry.enabled || !registry.directory) {
    return Object.freeze({
      withLock(_resource, operation) { return operation(); },
      health() { return { status: 'ready', mode: scannerEnabled ? 'in-process-disabled-evidence-policy' : 'external-scanner-disabled' }; }
    });
  }
  return createFileMutex({
    directory: resolve(registry.directory, '.external-scan-policy-locks'),
    leaseMs: 10_000,
    acquireTimeoutMs: 2_000,
    retryMs: 10
  });
}
function positiveInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 1_000_000) throw new EvidenceValidationError(`${field} must be a positive integer.`, { field });
  return parsed;
}
