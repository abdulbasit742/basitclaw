import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const STATUS_ROUTE = '/api/workforce-audit/external-scanner/status';
const ATTESTATIONS_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/external-scans$/;

export function createExternalScanManagementHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.externalScanStatus !== 'function') throw new TypeError('An external-scan-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) { return pathname === STATUS_ROUTE || ATTESTATIONS_ROUTE.test(pathname); }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method !== 'GET') return notFound(res, requestId);
    const clientAddress = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      if (typeof rateLimiter?.consume === 'function') {
        const burst = rateLimiter.consume(`client:${clientAddress}`, 'burst');
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst);
      }
      principal = await authenticationGateway.authenticate(req);
      authenticationGateway.authorise(principal, 'governance:read');
      if (typeof rateLimiter?.consume === 'function') {
        const decision = rateLimiter.consume(`credential:${principal.keyId ?? principal.subject}:external-scan`, 'read');
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision);
      }
      if (url.pathname === STATUS_ROUTE) {
        return sendJson(res, 200, { success: true, data: registry.externalScanStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      const match = url.pathname.match(ATTESTATIONS_ROUTE);
      if (!match) return notFound(res, requestId);
      const evidenceId = decodeURIComponent(match[1]);
      registry.get(principal.tenantId, evidenceId);
      const data = registry.externalScanAttestations(principal.tenantId, evidenceId, {
        version: optionalPositiveInteger(url.searchParams.get('version')),
        limit: positiveInteger(url.searchParams.get('limit'), 100, 500)
      });
      return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed = { allowed: true };
        if (typeof rateLimiter?.consume === 'function') {
          try {
            failed = rateLimiter.consume(`authentication:${clientAddress}`, 'authFailure');
            applyRateHeaders(res, rateLimiter, failed);
          } catch (storeError) {
            if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError);
            throw storeError;
          }
        }
        record(securityTelemetry, {
          type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId,
          method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'external-scan-management' }
        });
        if (!failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, {
          type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason, boundary: 'external-scan-management' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return unavailable(res, requestId, error, error.code ?? 'UNAVAILABLE');
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError) {
        record(securityTelemetry, { type: 'external_scan.management_denied', severity: error instanceof EvidenceStoreError ? 'critical' : 'high', outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details: { reason: error.code } });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE });
}

function optionalPositiveInteger(value) { if (value === null) return null; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('version must be a positive integer.', { field: 'version' }); return parsed; }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message = 'The external scanner management rate limit has been exceeded.') { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, code = error.code) { return sendJson(res, 503, { success: false, error: error.message, code, meta: { requestId } }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('External scanner management telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'External scanner route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
