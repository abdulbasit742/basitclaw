import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceAssuranceBundleAwareApp } from './evidenceAssuranceBundleServer.js';
import { createEvidenceAssuranceExportApprovalHandler } from './evidenceAssuranceExportApprovalHandler.js';
import { createEvidenceAssuranceExportApprovalRegistryFromEnvironment } from './evidenceAssuranceExportApprovalRegistry.js';

export function createEvidenceAssuranceExportApprovalAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceAssuranceExportApprovalRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceAssuranceBundleAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  approvalAuthenticationGateway = permissionAdapter(baseApp.authenticationGateway),
  approvalHandler = createEvidenceAssuranceExportApprovalHandler({
    registry: evidenceRegistry,
    authenticationGateway: approvalAuthenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  if (evidenceRegistry.assuranceExportApprovalEnabled && !evidenceRegistry.assuranceBundleEnabled) {
    throw new TypeError('Assurance export approvals require enabled assurance bundle delivery.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The assurance bundle application must expose a request handler.');
  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (approvalHandler.matches(url.pathname, req.method)) return await approvalHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled assurance export approval server error', { requestId, code: error?.code, error: error?.message });
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId });
        return res.end(JSON.stringify({ success: false, error: 'Internal server error.', code: 'INTERNAL_ERROR', meta: { requestId } }));
      }
      res.destroy(error);
    }
  });
  server.once('listening', () => baseApp.resilienceScheduler?.start?.());
  server.once('close', () => baseApp.resilienceScheduler?.stop?.());
  for (const property of [
    'resilienceScheduler','apiSecurity','authenticationGateway','identityEntitlements','privilegedAccess','scimHandler',
    'evidenceHandler','evidenceReferenceMutex','externalScanCallbackHandler','externalScanManagementHandler',
    'externalScanJobGovernanceHandler','externalScanJobDeliveryHandler','evidencePreservationHandler',
    'evidenceTimeAttestationHandler','evidenceTimeAttestationGovernanceHandler','evidenceAssuranceBundleHandler','auditRegistry'
  ]) server[property] = baseApp[property];
  server.evidenceRegistry = evidenceRegistry;
  server.evidenceAssuranceExportApprovalHandler = approvalHandler;
  return server;
}

function permissionAdapter(authenticationGateway) {
  if (!authenticationGateway || typeof authenticationGateway.authorise !== 'function') throw new TypeError('An authentication gateway is required.');
  return Object.freeze({
    ...authenticationGateway,
    authenticate: authenticationGateway.authenticate.bind(authenticationGateway),
    authorise(principal, permission) {
      const mapped = permission === 'evidence:export-request' || permission === 'evidence:export-materialize'
        ? 'evidence:export'
        : permission === 'evidence:export-approve' ? 'privileged:approve' : permission;
      return authenticationGateway.authorise(principal, mapped);
    }
  });
}
