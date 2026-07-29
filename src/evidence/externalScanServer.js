import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceAwareApp } from './evidenceServer.js';
import { createExternalScanCallbackHandler } from './externalScanCallbackHandler.js';
import { createExternalScanEvidenceRegistryFromEnvironment } from './externalScanEvidenceRegistry.js';
import { createExternalScanJobDeliveryHandler } from './externalScanJobDeliveryHandler.js';
import { createExternalScanJobGovernanceHandler } from './externalScanJobGovernanceHandler.js';
import { createExternalScanManagementHandler } from './externalScanManagementHandler.js';

export function createExternalScanAwareApp({
  env = process.env,
  evidenceRegistry = createExternalScanEvidenceRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceAwareApp({ env, evidenceRegistry, rateLimiter }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  callbackHandler = createExternalScanCallbackHandler({ registry: evidenceRegistry, rateLimiter, securityTelemetry }),
  managementHandler = createExternalScanManagementHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  }),
  jobGovernanceHandler = createExternalScanJobGovernanceHandler({
    registry: evidenceRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  }),
  jobDeliveryHandler = createExternalScanJobDeliveryHandler({ registry: evidenceRegistry, rateLimiter, securityTelemetry })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The evidence application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (callbackHandler.matches(url.pathname)) return await callbackHandler.handle(req, res, requestId);
      if (jobDeliveryHandler.matches(url.pathname)) return await jobDeliveryHandler.handle(req, res, requestId);
      if (jobGovernanceHandler.matches(url.pathname)) return await jobGovernanceHandler.handle(req, res, requestId);
      if (managementHandler.matches(url.pathname)) return await managementHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled external scanner server error', { requestId, code: error?.code, error: error?.message });
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
  server.externalScanCallbackHandler = callbackHandler;
  server.externalScanManagementHandler = managementHandler;
  server.externalScanJobGovernanceHandler = jobGovernanceHandler;
  server.externalScanJobDeliveryHandler = jobDeliveryHandler;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}
