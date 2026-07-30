import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from './evidenceTimeAttestationGovernanceServer.js';
import { createEvidenceAssuranceBundleHandler } from './evidenceAssuranceBundleHandler.js';
import { createEvidenceAssuranceBundleRegistryFromEnvironment } from './evidenceAssuranceBundleRegistry.js';

export function createEvidenceAssuranceBundleAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceAssuranceBundleRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationGovernanceAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  assuranceBundleHandler = createEvidenceAssuranceBundleHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  if (evidenceRegistry.assuranceBundleEnabled && !evidenceRegistry.enabled) {
    throw new TypeError('Evidence assurance bundles require enabled encrypted evidence custody.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The time-attestation governance application must expose a request handler.');
  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (assuranceBundleHandler.matches(url.pathname)) return await assuranceBundleHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled assurance bundle server error', { requestId, code: error?.code, error: error?.message });
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
    'resilienceScheduler', 'apiSecurity', 'authenticationGateway', 'identityEntitlements', 'privilegedAccess', 'scimHandler',
    'evidenceHandler', 'evidenceReferenceMutex', 'externalScanCallbackHandler', 'externalScanManagementHandler',
    'externalScanJobGovernanceHandler', 'externalScanJobDeliveryHandler', 'evidencePreservationHandler',
    'evidenceTimeAttestationHandler', 'evidenceTimeAttestationGovernanceHandler', 'auditRegistry'
  ]) server[property] = baseApp[property];
  server.evidenceRegistry = evidenceRegistry;
  server.evidenceAssuranceBundleHandler = assuranceBundleHandler;
  return server;
}
