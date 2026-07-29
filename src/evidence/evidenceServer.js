import { PassThrough } from 'node:stream';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { createRuntimeWorkforceAuditRegistry } from '../coordination/coordinatedRegistry.js';
import { createFederatedApp } from '../federatedServer.js';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { createAdaptiveRateLimiterFromEnvironment } from '../security/rateLimiter.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import { createEvidenceHandler } from './evidenceHandler.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError,
  createEvidenceRegistryFromEnvironment
} from './evidenceRegistry.js';

export function createEvidenceAwareApp({
  env = process.env,
  evidenceRegistry = createEvidenceRegistryFromEnvironment(env),
  auditRegistry = createRuntimeWorkforceAuditRegistry({ env }),
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(env),
  baseApp = createFederatedApp({ env, registry: auditRegistry, rateLimiter }),
  authenticationGateway = baseApp.authenticationGateway,
  securityTelemetry = baseApp.apiSecurity?.securityTelemetry,
  evidenceHandler = createEvidenceHandler({
    registry: evidenceRegistry,
    auditRegistry,
    authenticationGateway,
    securityTelemetry
  })
} = {}) {
  const baseHandler = baseApp.listeners('request')[0];
  if (typeof baseHandler !== 'function') throw new TypeError('The federated application must expose a request handler.');

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/health') {
      const requestId = randomUUID();
      const health = evidenceRegistry.health();
      if (health.required && health.status !== 'ready') {
        return sendJson(res, 503, {
          success: false,
          data: { status: 'degraded', evidence: publicHealth(health) },
          code: 'EVIDENCE_STORE_UNAVAILABLE',
          meta: { requestId }
        }, requestId, { 'retry-after': '30' });
      }
      return baseHandler(req, res);
    }

    if (evidenceHandler.matches(url.pathname)) return handleEvidenceRequest(req, res, url);
    if (req.method === 'POST' && url.pathname === '/api/workforce-audit/findings' && evidenceRegistry.enabled) {
      return validateFindingEvidence(req, res);
    }
    return baseHandler(req, res);
  });

  async function handleEvidenceRequest(req, res, url) {
    const requestId = randomUUID();
    const clientAddress = typeof rateLimiter.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter.consume(`client:${clientAddress}`, 'burst');
      applyRateDecision(res, rateLimiter, burst);
      if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      principal = await authenticationGateway.authenticate(req);
      const policy = evidencePolicy(req.method, url.pathname);
      const decision = rateLimiter.consume(`credential:${principal.keyId ?? principal.subject}:client:${clientAddress}`, policy);
      applyRateDecision(res, rateLimiter, decision);
      if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence request rate limit has been exceeded.');
      return await evidenceHandler.handle(req, res, principal, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed;
        try {
          failed = rateLimiter.consume(`authentication:${clientAddress}`, 'authFailure');
          applyRateDecision(res, rateLimiter, failed);
        } catch (storeError) {
          if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError);
          throw storeError;
        }
        safeRecord(securityTelemetry, {
          type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId,
          method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'evidence' }
        });
        if (!failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': challenge(authenticationGateway.mode)
        });
      }
      if (error instanceof AuthorizationError) {
        safeRecord(securityTelemetry, {
          type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason, boundary: 'evidence' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId);
      }
      if (error instanceof RateLimitStoreError) return unavailable(res, requestId, error);
      if (error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, 'OIDC_UNAVAILABLE');
      throw error;
    }
  }

  async function validateFindingEvidence(req, res) {
    let principal;
    try {
      principal = await authenticationGateway.authenticate(req);
      authenticationGateway.authorise(principal, 'finding:write');
    } catch {
      return baseHandler(req, res);
    }
    const requestId = randomUUID();
    try {
      const bodyBuffer = await readBody(req, 1_000_000);
      let input;
      try { input = JSON.parse(bodyBuffer.toString('utf8') || '{}'); }
      catch { return forwardBuffered(req, res, bodyBuffer); }
      evidenceRegistry.assertUsableReferences(principal.tenantId, input.evidenceRefs);
      return forwardBuffered(req, res, bodyBuffer);
    } catch (error) {
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError) {
        safeRecord(securityTelemetry, {
          type: error instanceof EvidenceStoreError ? 'evidence.store_unavailable' : 'evidence.reference_denied',
          severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high',
          outcome: 'denied', requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: '/api/workforce-audit/findings', details: { reason: error.code }
        });
        return sendJson(res, error.statusCode ?? 500, {
          success: false, error: error.message, code: error.code, details: error.details,
          meta: { requestId, tenantId: principal.tenantId, keyId: principal.keyId }
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  function forwardBuffered(original, res, bodyBuffer) {
    const replay = new PassThrough();
    replay.method = original.method;
    replay.url = original.url;
    replay.headers = { ...original.headers, 'content-length': String(bodyBuffer.length) };
    replay.rawHeaders = original.rawHeaders;
    replay.httpVersion = original.httpVersion;
    replay.httpVersionMajor = original.httpVersionMajor;
    replay.httpVersionMinor = original.httpVersionMinor;
    replay.socket = original.socket;
    replay.connection = original.connection;
    replay.complete = true;
    replay.end(bodyBuffer);
    return baseHandler(replay, res);
  }

  server.once('listening', () => baseApp.resilienceScheduler?.start?.());
  server.once('close', () => baseApp.resilienceScheduler?.stop?.());
  server.resilienceScheduler = baseApp.resilienceScheduler;
  server.apiSecurity = baseApp.apiSecurity;
  server.authenticationGateway = authenticationGateway;
  server.identityEntitlements = baseApp.identityEntitlements;
  server.privilegedAccess = baseApp.privilegedAccess;
  server.scimHandler = baseApp.scimHandler;
  server.evidenceRegistry = evidenceRegistry;
  server.evidenceHandler = evidenceHandler;
  server.auditRegistry = auditRegistry;
  return server;
}

export function prepareEvidenceLifecycle({ app } = {}) {
  const health = app?.evidenceRegistry?.health?.() ?? { status: 'disabled', enabled: false, required: false };
  if (health.required && health.status !== 'ready') {
    const error = new EvidenceStoreError('The required evidence lifecycle is not ready.', { health: publicHealth(health) });
    throw error;
  }
  return health;
}

function evidencePolicy(method, pathname) {
  if (method === 'GET') return 'read';
  if (/\/(legal-hold|release-hold|dispose|verify)$/.test(pathname)) return 'sensitive';
  return 'write';
}

async function readBody(req, maximumBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) {
      const error = new EvidenceValidationError('Finding request body exceeds the 1 MB limit.', { field: 'body' });
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function publicHealth(value) {
  if (!value || typeof value !== 'object') return value;
  const clone = structuredClone(value);
  delete clone.directory;
  delete clone.primaryKeyId;
  delete clone.configuredKeyIds;
  if (clone.mutex) delete clone.mutex.directory;
  return clone;
}

function applyRateDecision(res, limiter, decision) {
  const headers = typeof limiter.headers === 'function' ? limiter.headers(decision) : {};
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
}
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: { requestId } }, requestId, { 'retry-after': '30' }); }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function safeRecord(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence boundary telemetry failed', error); } }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
