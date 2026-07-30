import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from './evidenceTimeAttestationGovernanceServer.js';
import { createEvidenceDisclosureHandler } from './evidenceDisclosureHandler.js';
import { createEvidenceDisclosureRegistryFromEnvironment } from './evidenceDisclosureRegistry.js';

export function createEvidenceDisclosureAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceDisclosureRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationGovernanceAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  disclosureHandler = createEvidenceDisclosureHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  if (evidenceRegistry.evidenceDisclosureEnabled
      && (!evidenceRegistry.evidenceTimeAttestationEnabled || !evidenceRegistry.evidenceTimeAttestationGovernanceEnabled)) {
    throw new TypeError('Portable evidence disclosures require enabled time attestations and notary governance.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The governed time-attestation application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (disclosureHandler.matches(url.pathname)) return await disclosureHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled evidence disclosure server error', { requestId, code: error?.code, error: error?.message });
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
  server.evidenceDisclosureHandler = disclosureHandler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}
