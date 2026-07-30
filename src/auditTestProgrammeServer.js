import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createEvidenceTimeAttestationAwareApp } from './evidence/evidenceTimeAttestationServer.js';
import { createAdaptiveRateLimiterFromEnvironment } from './security/rateLimiter.js';
import { createAuditTestProgrammeHandler } from './auditTestProgrammeHandler.js';

export function createAuditTestProgrammeAwareApp({
  env = process.env,
  baseApp = createEvidenceTimeAttestationAwareApp({ env }),
  auditRegistry = baseApp.auditRegistry,
  rateLimiter = baseApp.apiSecurity?.rateLimiter ?? createAdaptiveRateLimiterFromEnvironment(env),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  testProgrammeHandler = createAuditTestProgrammeHandler({
    registry: auditRegistry,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The evidence time-attestation application must expose a request handler.');
  if (!auditRegistry || typeof auditRegistry.forTenant !== 'function') throw new TypeError('The application must expose its workforce-audit registry.');

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (testProgrammeHandler.matches(url.pathname)) return await testProgrammeHandler.handle(req, res, requestId);
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled audit test-programme server error', {
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
  server.evidenceRegistry = baseApp.evidenceRegistry;
  server.evidenceHandler = baseApp.evidenceHandler;
  server.evidenceReferenceMutex = baseApp.evidenceReferenceMutex;
  server.externalScanCallbackHandler = baseApp.externalScanCallbackHandler;
  server.externalScanManagementHandler = baseApp.externalScanManagementHandler;
  server.externalScanJobGovernanceHandler = baseApp.externalScanJobGovernanceHandler;
  server.externalScanJobDeliveryHandler = baseApp.externalScanJobDeliveryHandler;
  server.evidencePreservationHandler = baseApp.evidencePreservationHandler;
  server.evidenceTimeAttestationHandler = baseApp.evidenceTimeAttestationHandler;
  server.auditTestProgrammeHandler = testProgrammeHandler;
  server.auditRegistry = auditRegistry;
  return server;
}
