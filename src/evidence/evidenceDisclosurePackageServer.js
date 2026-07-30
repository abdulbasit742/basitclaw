import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationAwareApp } from './evidenceTimeAttestationServer.js';
import { createEvidenceDisclosurePackageHandler } from './evidenceDisclosurePackageHandler.js';
import { createEvidenceDisclosurePackageRegistryFromEnvironment } from './evidenceDisclosurePackageRegistry.js';

export function createEvidenceDisclosurePackageAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceDisclosurePackageRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  disclosureHandler = null
} = {}) {
  if (evidenceRegistry.evidenceDisclosureEnabled && !evidenceRegistry.enabled) {
    throw new TypeError('Evidence disclosure packages require enabled evidence custody.');
  }
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The time-attestation application must expose a request handler.');
  const exportAuthenticationGateway = createExportAuthenticationGateway(baseApp.authenticationGateway);
  const handler = disclosureHandler ?? createEvidenceDisclosurePackageHandler({
    registry: evidenceRegistry,
    authenticationGateway: exportAuthenticationGateway,
    rateLimiter,
    securityTelemetry
  });

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (handler.matches(url.pathname)) return await handler.handle(req, res, requestId);
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
  server.evidenceDisclosureAuthenticationGateway = exportAuthenticationGateway;
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
  server.evidenceDisclosurePackageHandler = handler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}

function createExportAuthenticationGateway(authenticationGateway) {
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') {
    throw new TypeError('An authentication gateway is required for evidence disclosure.');
  }
  return Object.freeze({
    mode: authenticationGateway.mode,
    async authenticate(req) {
      const principal = await authenticationGateway.authenticate(req);
      const existing = Array.isArray(principal.permissions) ? principal.permissions : [];
      const canDeriveExport = existing.includes('governance:read') && existing.includes('evidence:preserve');
      const permissions = canDeriveExport && !existing.includes('evidence:export')
        ? [...existing, 'evidence:export']
        : existing;
      return Object.freeze({ ...principal, permissions });
    },
    authorise(principal, permission) {
      return authenticationGateway.authorise(principal, permission);
    }
  });
}
