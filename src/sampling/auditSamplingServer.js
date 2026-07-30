import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceAssuranceBundleAwareApp } from '../evidence/evidenceAssuranceBundleServer.js';
import { createAuditSamplingHandler } from './auditSamplingHandler.js';
import { createAuditSamplingRegistryFromEnvironment } from './auditSamplingRegistry.js';

export function createAuditSamplingAwareApp({
  env = process.env,
  evidenceRegistry = createAuditSamplingRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceAssuranceBundleAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  auditSamplingHandler = createAuditSamplingHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  if (evidenceRegistry.auditSamplingEnabled && !evidenceRegistry.enabled) {
    throw new TypeError('Audit sampling requires enabled encrypted evidence custody.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The evidence assurance application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (auditSamplingHandler.matches(url.pathname)) return await auditSamplingHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled audit sampling server error', { requestId, code: error?.code, error: error?.message });
      if (!res.headersSent) {
        res.writeHead(500, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-request-id': requestId
        });
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
    'evidenceTimeAttestationHandler', 'evidenceTimeAttestationGovernanceHandler', 'evidenceAssuranceBundleHandler', 'auditRegistry'
  ]) server[property] = baseApp[property];
  server.evidenceRegistry = evidenceRegistry;
  server.auditSamplingHandler = auditSamplingHandler;
  return server;
}
