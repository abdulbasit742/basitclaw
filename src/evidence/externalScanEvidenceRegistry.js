import { EvidenceConflictError } from './evidenceRegistry.js';
import { createScreenedEvidenceRegistryFromEnvironment } from './evidenceScreeningRegistry.js';
import {
  ExternalScanRequiredError,
  createExternalScanAttestationRegistryFromEnvironment
} from './externalScanAttestationRegistry.js';

export function createExternalScanEvidenceRegistry({ registry, attestations } = {}) {
  if (!registry || typeof registry.screeningReport !== 'function') throw new TypeError('A screened evidence registry is required.');
  if (!attestations || typeof attestations.list !== 'function') throw new TypeError('An external scan attestation registry is required.');

  function recordExternalScanAttestation(bodyBuffer, headers) {
    return attestations.acceptSigned(bodyBuffer, headers, (attestation) => {
      const report = registry.screeningReport(attestation.tenantId, attestation.evidenceId, { version: attestation.version });
      return { version: report.version, contentSha256: report.contentSha256 };
    });
  }

  function externalScanAttestations(tenantId, evidenceId, options = {}) {
    return attestations.list(tenantId, { evidenceId, ...options });
  }

  function externalScanStatus(tenantId) {
    return attestations.tenantStatus(tenantId);
  }

  function releaseQuarantine(tenantId, evidenceId, input, context = {}) {
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
  }

  function get(tenantId, evidenceId) {
    return withExternalScan(tenantId, registry.get(tenantId, evidenceId));
  }

  function list(tenantId, options = {}) {
    return registry.list(tenantId, options).map((item) => withExternalScan(tenantId, item));
  }

  function screeningReport(tenantId, evidenceId, options = {}) {
    const report = registry.screeningReport(tenantId, evidenceId, options);
    return { ...report, externalScan: attestations.latest(tenantId, evidenceId, report.version) };
  }

  function verify(tenantId, evidenceId = null) {
    const result = registry.verify(tenantId, evidenceId);
    return { ...result, externalScan: attestations.verify(tenantId) };
  }

  function health() {
    const base = registry.health();
    const externalScan = attestations.health();
    const unavailable = externalScan.requiredForRelease && externalScan.status !== 'ready';
    return { ...base, status: unavailable ? 'unavailable' : base.status, externalScan };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    try {
      const externalScan = attestations.tenantStatus(tenantId);
      const unavailable = attestations.requiredForRelease && externalScan.status === 'unavailable';
      return {
        ...base,
        status: unavailable ? 'unavailable' : base.status === 'unavailable' ? 'unavailable' : externalScan.status === 'attention' ? 'attention' : base.status,
        externalScan
      };
    } catch (error) {
      return {
        ...base,
        status: attestations.requiredForRelease ? 'unavailable' : base.status,
        externalScan: { status: 'unavailable', mode: attestations.mode, requiredForRelease: attestations.requiredForRelease, error: error?.code ?? 'external_scan_store_unavailable' }
      };
    }
  }

  function withExternalScan(tenantId, item) {
    if (!item || item.status === 'disposed') return item;
    const latest = attestations.latest(tenantId, item.evidenceId, item.currentVersion);
    return { ...item, externalScan: latest };
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
    externalScanAttestationRegistry: attestations,
    externalScanEnabled: attestations.enabled
  });
}

export function createExternalScanEvidenceRegistryFromEnvironment(env = process.env) {
  const registry = createScreenedEvidenceRegistryFromEnvironment(env);
  const attestations = createExternalScanAttestationRegistryFromEnvironment({ env, evidenceRegistry: registry });
  if (!registry.enabled && attestations.enabled) throw new EvidenceConflictError('External scanner attestations require enabled evidence custody.');
  return createExternalScanEvidenceRegistry({ registry, attestations });
}
