import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationAwareApp } from './evidenceTimeAttestationServer.js';
import { createEvidenceDisclosureHandler } from './evidenceDisclosureHandler.js';
import { createEvidenceDisclosureRegistryFromEnvironment } from './evidenceDisclosureRegistry.js';

export function createEvidenceDisclosureAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceDisclosureRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  disclosureAuthenticationGateway = createDisclosureAuthenticationGateway(baseApp.authenticationGateway),
  disclosureHandler = createEvidenceDisclosureHandler({
    registry: evidenceRegistry,
    authenticationGateway: disclosureAuthenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') {
    throw new TypeError('The time-attestation application must expose a request handler.');
  }

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (disclosureHandler.matches(url.pathname)) {
        return await disclosureHandler.handle(req, res, requestId);
      }
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled evidence disclosure server error', {
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
  server.disclosureAuthenticationGateway = disclosureAuthenticationGateway;
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
  server.evidenceDisclosureHandler = disclosureHandler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}

function createDisclosureAuthenticationGateway(authenticationGateway) {
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function'
      || typeof authenticationGateway.authorise !== 'function') {
    throw new TypeError('An authentication gateway is required for evidence disclosures.');
  }
  return Object.freeze({
    mode: authenticationGateway.mode,
    authenticate: authenticationGateway.authenticate.bind(authenticationGateway),
    authorise(principal, permission) {
      const mappedPermission = permission === 'evidence:disclose:approve'
        ? 'backup:restore'
        : permission === 'evidence:disclose'
          ? 'governance:read'
          : permission;
      return authenticationGateway.authorise(principal, mappedPermission);
    }
  });
}
