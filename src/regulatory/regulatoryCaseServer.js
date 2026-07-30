import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from '../evidence/evidenceTimeAttestationGovernanceServer.js';
import { createRegulatoryCaseHandler } from './regulatoryCaseHandler.js';
import { createRegulatoryCaseStoreFromEnvironment } from './regulatoryCaseStore.js';

export function createRegulatoryCaseAwareApp({
  env = process.env,
  baseApp = createEvidenceTimeAttestationGovernanceAwareApp({ env }),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  regulatoryCaseStore = createRegulatoryCaseStoreFromEnvironment({ env, evidenceRegistry: baseApp.evidenceRegistry }),
  regulatoryAuthenticationGateway = createRegulatoryAuthenticationGateway(baseApp.authenticationGateway),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  regulatoryCaseHandler = createRegulatoryCaseHandler({ store: regulatoryCaseStore, authenticationGateway: regulatoryAuthenticationGateway, rateLimiter, securityTelemetry })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The evidence governance application must expose a request handler.');
  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (regulatoryCaseHandler.matches(url.pathname)) return await regulatoryCaseHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled regulatory case server error', { requestId, code: error?.code, error: error?.message });
      if (!res.headersSent) {
        res.writeHead(500, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId });
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
  server.regulatoryAuthenticationGateway = regulatoryAuthenticationGateway;
  server.identityEntitlements = baseApp.identityEntitlements;
  server.privilegedAccess = baseApp.privilegedAccess;
  server.scimHandler = baseApp.scimHandler;
  server.evidenceRegistry = baseApp.evidenceRegistry;
  server.evidenceHandler = baseApp.evidenceHandler;
  server.evidenceReferenceMutex = baseApp.evidenceReferenceMutex;
  server.externalScanCallbackHandler = baseApp.externalScanCallbackHandler;
  server.externalScanManagementHandler = baseApp.externalScanManagementHandler;
  server.externalScanJobGovernanceHandler = baseApp.externalScanJobGovernanceHandler;
  server.externalScanJobDeliveryHandler = baseApp.externalScanJobDeliveryHandler;
  server.evidencePreservationHandler = baseApp.evidencePreservationHandler;
  server.evidenceTimeAttestationHandler = baseApp.evidenceTimeAttestationHandler;
  server.evidenceTimeAttestationGovernanceHandler = baseApp.evidenceTimeAttestationGovernanceHandler;
  server.regulatoryCaseStore = regulatoryCaseStore;
  server.regulatoryCaseHandler = regulatoryCaseHandler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}

function createRegulatoryAuthenticationGateway(authenticationGateway) {
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function' || typeof authenticationGateway.authorise !== 'function') throw new TypeError('An authentication gateway is required for regulatory cases.');
  return Object.freeze({
    mode: authenticationGateway.mode,
    authenticate: authenticationGateway.authenticate.bind(authenticationGateway),
    authorise(principal, permission) {
      const mapped = permission === 'regulatory:case:approve' ? 'backup:restore' : permission === 'regulatory:case' ? 'governance:read' : permission;
      return authenticationGateway.authorise(principal, mapped);
    }
  });
}
