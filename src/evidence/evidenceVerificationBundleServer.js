import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { createEvidenceTimeAttestationGovernanceAwareApp } from './evidenceTimeAttestationGovernanceServer.js';
import { createEvidenceTimeAttestationGovernanceRegistryFromEnvironment } from './evidenceTimeAttestationGovernanceRegistry.js';
import {
  createEvidenceVerificationBundleServiceFromEnvironment
} from './evidenceVerificationBundle.js';
import { createEvidenceVerificationBundleHandler } from './evidenceVerificationBundleHandler.js';

export function createEvidenceVerificationBundleAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceTimeAttestationGovernanceRegistryFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createEvidenceTimeAttestationGovernanceAwareApp({ env, evidenceRegistry, rateLimiter }),
  verificationRegistry = operationalProofRegistry(evidenceRegistry),
  verificationBundleService = createEvidenceVerificationBundleServiceFromEnvironment({ env, registry: verificationRegistry }),
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  verificationBundleHandler = createEvidenceVerificationBundleHandler({
    service: verificationBundleService,
    authenticationGateway: baseApp.authenticationGateway,
    rateLimiter,
    securityTelemetry
  })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The notary-governance application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const requestId = randomUUID();
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (verificationBundleHandler.matches(url.pathname)) {
        return await verificationBundleHandler.handle(req, res, requestId);
      }
      return await baseHandler(req, res);
    } catch (error) {
      console.error('Unhandled evidence verification-bundle server error', {
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
  server.evidenceVerificationBundleHandler = verificationBundleHandler;
  server.evidenceVerificationBundleService = verificationBundleService;
  server.auditRegistry = baseApp.auditRegistry;
  return server;
}

export function operationalProofRegistry(registry) {
  return Object.freeze({
    ...registry,
    verifyEvidenceTimeAttestations(tenantId, archiveId) {
      const result = registry.verifyEvidenceTimeAttestations(tenantId, archiveId);
      return {
        ...result,
        quorumSatisfied: result.operationalQuorumSatisfied ?? result.quorumSatisfied,
        distinctProviders: result.acceptableDistinctProviders ?? result.distinctProviders,
        providerIds: result.acceptableProviderIds ?? result.providerIds,
        governanceRequiredForDisposition: registry.evidenceTimeAttestationGovernanceStore?.requiredForDisposition ?? false
      };
    },
    evidenceTimeAttestations(tenantId, archiveId, options = {}) {
      const effective = registry.effectiveArchiveVerification?.(tenantId, archiveId);
      if (effective?.attestationDecisions) {
        const limit = Math.min(Math.max(Number(options.limit ?? 5000), 1), 5000);
        return effective.attestationDecisions
          .filter((entry) => entry.governance?.operationallyAcceptable === true)
          .slice(-limit);
      }
      return registry.evidenceTimeAttestations(tenantId, archiveId, options);
    }
  });
}
