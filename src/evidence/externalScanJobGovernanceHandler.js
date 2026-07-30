import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import { ExternalScanJobStoreError } from './externalScanJobOutbox.js';

const STATUS_ROUTE = '/api/workforce-audit/external-scan-delivery/status';
const JOBS_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/external-scan-jobs$/;

export function createExternalScanJobGovernanceHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.queueExternalScanJob !== 'function') throw new TypeError('A scan-job-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) { return pathname === STATUS_ROUTE || JOBS_ROUTE.test(pathname); }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      const permission = req.method === 'POST' ? 'evidence:scan' : 'governance:read';
      authenticationGateway.authorise(principal, permission);
      const policy = req.method === 'POST' ? 'write' : 'read';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:external-scan-jobs`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The external scan job request rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.externalScanJobStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      const match = url.pathname.match(JOBS_ROUTE);
      if (!match) return notFound(res, requestId);
      const evidenceId = decodePathSegment(match[1], 'evidenceId');
      registry.get(principal.tenantId, evidenceId);
      if (req.method === 'GET') {
        const data = registry.externalScanJobs(principal.tenantId, evidenceId, {
          limit: positiveInteger(url.searchParams.get('limit'), 100, 500)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (req.method === 'POST') {
        const input = await readJson(req, 16_384, new Set(['providerId', 'version']));
        const data = registry.queueExternalScanJob(principal.tenantId, evidenceId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: data.duplicate ? 'external_scan.job_duplicate' : 'external_scan.job_queued',
          severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { jobId: data.job.jobId, evidenceId, providerId: data.job.providerId, version: data.job.evidenceVersion }
        });
        return sendJson(res, data.duplicate ? 200 : 202, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      return notFound(res, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed;
        try {
          failed = rateLimiter?.consume?.(`authentication:${client}`, 'authFailure');
          if (failed) applyRateHeaders(res, rateLimiter, failed);
        } catch (storeError) {
          if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError, principal);
          throw storeError;
        }
        record(securityTelemetry, { type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'external-scan-jobs' } });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, { type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details: { reason: error.details?.reason, boundary: 'external-scan-jobs' } });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, { success: false, error: 'The external scan job boundary is busy. Retry the request.', code: 'EXTERNAL_SCAN_JOB_BUSY', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'EXTERNAL_SCAN_JOB_STORE_UNAVAILABLE');
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError || error instanceof ExternalScanJobStoreError) {
        record(securityTelemetry, { type: 'external_scan.job_denied', severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high', outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details: { reason: error.code } });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE });
}

async function readJson(req, maximumBytes, allowed) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('External scan job requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('External scan job request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('External scan job request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('External scan job request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`External scan job request contains unsupported field ${key}.`, { field: key });
  return input;
}
function decodePathSegment(value, field) {
  try { return decodeURIComponent(value); }
  catch { throw new EvidenceValidationError(`The ${field} path segment contains invalid percent encoding.`, { field }); }
}
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('External scan job telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'External scan job route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
