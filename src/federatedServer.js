import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { createRuntimeWorkforceAuditRegistry } from './coordination/coordinatedRegistry.js';
import { createApp } from './server.js';
import { AuthenticationError, AuthorizationError } from './security/accessControl.js';
import { createAuthenticationGatewayFromEnvironment } from './security/authenticationGateway.js';
import { OidcUnavailableError } from './security/oidcAuthenticator.js';
import { createAdaptiveRateLimiterFromEnvironment } from './security/rateLimiter.js';
import { RateLimitStoreError } from './security/sharedRateLimiter.js';
import { createSecurityEventArchiveFromEnvironment } from './security/securityEventArchive.js';
import { createSecurityTelemetryFromEnvironment } from './security/securityTelemetry.js';

export function createFederatedApp({
  env = process.env,
  registry = createRuntimeWorkforceAuditRegistry(),
  authenticationGateway = createAuthenticationGatewayFromEnvironment(env),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  securityArchive = createSecurityEventArchiveFromEnvironment(env),
  securityTelemetry = createSecurityTelemetryFromEnvironment(env, { archive: securityArchive }),
  resilienceScheduler = null,
  innerAppFactory = createApp
} = {}) {
  const authenticatedRequests = new WeakMap();
  const trustedAccessController = createTrustedAccessController(authenticationGateway, authenticatedRequests);
  const inner = innerAppFactory({
    registry,
    accessController: trustedAccessController,
    resilienceScheduler,
    rateLimiter,
    securityArchive,
    securityTelemetry
  });
  const innerHandler = inner.listeners('request')[0];
  if (typeof innerHandler !== 'function') throw new TypeError('The workforce-audit inner application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (!url.pathname.startsWith('/api/workforce-audit/')) return innerHandler(req, res);
    const authorization = headerValue(req.headers.authorization);
    const requiresPreAuthentication = Boolean(authorization) || authenticationGateway.mode === 'oidc';
    if (!requiresPreAuthentication) return innerHandler(req, res);

    const requestId = randomUUID();
    const clientAddress = typeof rateLimiter.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    try {
      const principal = await authenticationGateway.authenticate(req);
      authenticatedRequests.set(req, principal);
      return innerHandler(req, res);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failedDecision;
        try {
          failedDecision = rateLimiter.consume(`authentication:${clientAddress}`, 'authFailure');
          applyRateDecision(res, rateLimiter, failedDecision);
        } catch (storeError) {
          if (storeError instanceof RateLimitStoreError) {
            return sendJson(res, 503, {
              success: false, error: storeError.message, code: storeError.code, details: storeError.details, meta: { requestId }
            }, requestId);
          }
          console.error('Federated authentication limiter failed', { requestId, error: storeError });
          return sendJson(res, 500, {
            success: false, error: 'Internal server error.', code: 'INTERNAL_ERROR', meta: { requestId }
          }, requestId);
        }
        safeRecordSecurityEvent(securityTelemetry, {
          type: 'authentication.failed',
          severity: error.code === 'UNAUTHENTICATED' ? 'warning' : 'high',
          outcome: 'denied',
          requestId,
          clientAddress,
          keyId: error.details?.keyId,
          method: req.method,
          route: url.pathname,
          details: { reason: error.details?.reason ?? error.code, authMethod: 'oidc' }
        });
        if (!failedDecision.allowed) {
          return sendJson(res, 429, {
            success: false,
            error: 'Too many failed authentication attempts.',
            code: 'RATE_LIMITED',
            details: failedDecision,
            meta: { requestId }
          }, requestId, { 'retry-after': String(failedDecision.retryAfterSeconds ?? 1) });
        }
        return sendJson(res, 401, {
          success: false, error: error.message, code: error.code, meta: { requestId }
        }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        safeRecordSecurityEvent(securityTelemetry, {
          type: error.details?.reason === 'tenant_override' ? 'tenant.override_attempted' : 'authorization.denied',
          severity: error.details?.reason === 'tenant_override' ? 'high' : 'warning',
          outcome: 'denied',
          requestId,
          clientAddress,
          keyId: error.details?.keyId,
          method: req.method,
          route: url.pathname,
          details: { reason: error.details?.reason, authMethod: 'oidc' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId);
      }
      if (error instanceof RateLimitStoreError) {
        return sendJson(res, 503, {
          success: false, error: error.message, code: error.code, details: error.details, meta: { requestId }
        }, requestId);
      }
      if (error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        safeRecordSecurityEvent(securityTelemetry, {
          type: 'identity_provider.unavailable', severity: 'critical', outcome: 'failed', requestId,
          clientAddress, method: req.method, route: url.pathname,
          details: { reason: error.details?.cause ?? error.code }
        });
        return sendJson(res, 503, {
          success: false, error: error.message, code: 'OIDC_UNAVAILABLE', meta: { requestId }
        }, requestId, { 'retry-after': '30' });
      }
      console.error('Unhandled federated authentication error', { requestId, error });
      return sendJson(res, 500, {
        success: false, error: 'Internal server error.', code: 'INTERNAL_ERROR', meta: { requestId }
      }, requestId);
    }
  });

  server.once('listening', () => inner.resilienceScheduler?.start?.());
  server.once('close', () => inner.resilienceScheduler?.stop?.());
  server.resilienceScheduler = inner.resilienceScheduler;
  server.apiSecurity = { ...inner.apiSecurity, authenticationGateway };
  server.authenticationGateway = authenticationGateway;
  return server;
}

function createTrustedAccessController(gateway, authenticatedRequests) {
  return {
    authenticate(req) {
      const principal = authenticatedRequests.get(req);
      if (principal) return principal;
      if (gateway.mode === 'oidc') {
        throw new AuthenticationError('A valid OIDC bearer token is required.', { code: 'OIDC_UNAUTHENTICATED' });
      }
      return gateway.apiKeyController.authenticate(req);
    },
    authorise: (principal, permission) => gateway.authorise(principal, permission),
    tenantIds: () => gateway.tenantIds(),
    credentialHealth: () => gateway.credentialHealth(),
    principalCount: gateway.principalCount
  };
}

function challenge(mode) {
  return mode === 'api-key'
    ? 'ApiKey realm="workforce-audit"'
    : mode === 'oidc'
      ? 'Bearer realm="workforce-audit"'
      : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"';
}

function applyRateDecision(res, rateLimiter, decision) {
  const headers = typeof rateLimiter.headers === 'function' ? rateLimiter.headers(decision) : {};
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
}

function safeRecordSecurityEvent(telemetry, input) {
  try { telemetry.record(input); } catch (error) { console.error('Security telemetry record failed', error); }
}

function sendJson(res, status, payload, requestId, additionalHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...additionalHeaders
  });
  res.end(JSON.stringify(payload));
}

function headerValue(value) {
  if (Array.isArray(value)) return value[0]?.trim() ?? '';
  return typeof value === 'string' ? value.trim() : '';
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  createFederatedApp().listen(port, () => console.log(`BasitClaw listening on http://localhost:${port}`));
}
