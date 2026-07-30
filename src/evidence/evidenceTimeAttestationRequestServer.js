import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from './evidenceTimeAttestationGovernanceServer.js';
import { createEvidenceTimeAttestationRequestHandler } from './evidenceTimeAttestationRequestHandler.js';
import { createEvidenceTimeAttestationRequestRegistryFromEnvironment } from './evidenceTimeAttestationRequestRegistry.js';

export function createEvidenceTimeAttestationRequestAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceTimeAttestationRequestRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationGovernanceAwareApp({ env, evidenceRegistry, rateLimiter }),
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
    throw new TypeError('The time-attestation governance application must expose a request handler.');
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
  server.resilienceScheduler = baseApp.resilienceScheduler;
  server.apiSecurity = baseApp.apiSecurity;
  server.authenticationGateway = baseApp.authenticationGateway;
  server.identityEntitlements = baseApp.identityEntitlements;
  server.privilegedAccess = baseApp.privilegedAccess;
  server.scimHandler = baseApp.scimHandler;
  server.evidenceRegistry = evidenceRegistry;
  server.evidenceHandler = baseApp.evidenceHandler;
  server.evidenceReferenceMutex = baseApp.evidenceReferenceMutex;
  server.externalScanCallbackHandler = baseApp.externalScanCallbackHandler;
  server.externalScanManagementHandler = baseApp.externalScanManagementHandler;
  server.externalScanJobGovernanceHandler = baseApp.externalScanJobGovernanceHandler;
  server.externalScanJobDeliveryHandler = baseApp.externalScanJobDeliveryHandler;
  server.evidencePreservationHandler = baseApp.evidencePreservationHandler;
  server.evidenceTimeAttestationHandler = baseApp.evidenceTimeAttestationHandler;
  server.evidenceTimeAttestationGovernanceHandler = baseApp.evidenceTimeAttestationGovernanceHandler;
  server.evidenceTimeAttestationRequestHandler = requestHandler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}
