import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createEvidenceAssuranceExportApprovalAwareApp } from '../evidence/evidenceAssuranceExportApprovalServer.js';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createRegulatoryCaseHandler } from './regulatoryCaseHandler.js';
import { createRegulatoryCaseStoreFromEnvironment } from './regulatoryCaseStore.js';

export function createRegulatoryCaseAwareApp({
  env = process.env,
  baseApp = createEvidenceAssuranceExportApprovalAwareApp({ env }),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  regulatoryCaseStore = createRegulatoryCaseStoreFromEnvironment({ env, evidenceRegistry: baseApp.evidenceRegistry }),
  regulatoryAuthenticationGateway = createRegulatoryAuthenticationGateway(baseApp.authenticationGateway),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  regulatoryCaseHandler = createRegulatoryCaseHandler({
    store: regulatoryCaseStore,
    authenticationGateway: regulatoryAuthenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') {
    throw new TypeError('The assurance export approval application must expose a request handler.');
  }
  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (regulatoryCaseHandler.matches(url.pathname)) {
        return await regulatoryCaseHandler.handle(req, res, requestId);
      }
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled regulatory case server error', {
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
    'resilienceScheduler', 'apiSecurity', 'authenticationGateway',
    'identityEntitlements', 'privilegedAccess', 'scimHandler',
    'evidenceHandler', 'evidenceReferenceMutex', 'externalScanCallbackHandler',
    'externalScanManagementHandler', 'externalScanJobGovernanceHandler',
    'externalScanJobDeliveryHandler', 'evidencePreservationHandler',
    'evidenceTimeAttestationHandler', 'evidenceTimeAttestationGovernanceHandler',
    'evidenceAssuranceBundleHandler', 'evidenceAssuranceExportApprovalHandler',
    'auditRegistry'
  ]) server[property] = baseApp[property];
  server.evidenceRegistry = baseApp.evidenceRegistry;
  server.regulatoryAuthenticationGateway = regulatoryAuthenticationGateway;
  server.regulatoryCaseStore = regulatoryCaseStore;
  server.regulatoryCaseHandler = regulatoryCaseHandler;
  return server;
}

function createRegulatoryAuthenticationGateway(authenticationGateway) {
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function'
      || typeof authenticationGateway.authorise !== 'function') {
    throw new TypeError('An authentication gateway is required for regulatory cases.');
  }
  return Object.freeze({
    mode: authenticationGateway.mode,
    authenticate: authenticationGateway.authenticate.bind(authenticationGateway),
    authorise(principal, permission) {
      const mapped = permission === 'regulatory:case:approve'
        ? 'backup:restore'
        : permission === 'regulatory:case'
          ? 'governance:read'
          : permission;
      return authenticationGateway.authorise(principal, mapped);
    }
  });
}
