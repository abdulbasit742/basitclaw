import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceAssuranceBundleAwareApp } from './evidenceAssuranceBundleServer.js';
import { createEvidenceTimeAttestationRequestHandler } from './evidenceTimeAttestationRequestHandler.js';
import { createEvidenceTimeAttestationRequestRegistryFromEnvironment } from './evidenceTimeAttestationRequestRegistry.js';

export function createEvidenceTimeAttestationRequestAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceTimeAttestationRequestRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceAssuranceBundleAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  requestHandler = createEvidenceTimeAttestationRequestHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  if (evidenceRegistry.evidenceTimeAttestationRequestEnabled
      && !evidenceRegistry.evidenceTimeAttestationEnabled) {
    throw new TypeError('Evidence-notary request delivery requires enabled time attestations.');
  }
  if (evidenceRegistry.evidenceTimeAttestationRequestEnabled
      && !evidenceRegistry.evidencePreservationEnabled) {
    throw new TypeError('Evidence-notary request delivery requires enabled immutable preservation.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') {
    throw new TypeError('The assurance bundle application must expose a request handler.');
  }

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (requestHandler.matches(url.pathname)) {
        return await requestHandler.handle(req, res, requestId);
      }
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled evidence-notary request server error', {
        requestId,
        code: error?.code,
        error: error?.message
      });
      if (!res.headersSent) {
        res.writeHead(500, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'x-request-id': requestId
        });
        return res.end(JSON.stringify({
          success: false,
          error: 'Internal server error.',
          code: 'INTERNAL_ERROR',
          meta: { requestId }
        }));
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
    'evidenceTimeAttestationHandler', 'evidenceTimeAttestationGovernanceHandler', 'evidenceAssuranceBundleHandler',
    'auditRegistry'
  ]) server[property] = baseApp[property];
  server.evidenceRegistry = evidenceRegistry;
  server.evidenceTimeAttestationRequestHandler = requestHandler;
  return server;
}
