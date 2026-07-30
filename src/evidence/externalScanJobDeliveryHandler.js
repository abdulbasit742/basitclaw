import { randomUUID } from 'node:crypto';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import { ExternalScanAuthenticationError } from './externalScanAttestationRegistry.js';
import { ExternalScanJobStoreError } from './externalScanJobOutbox.js';

const CLAIM_ROUTE = '/api/workforce-audit/external-scanner/jobs/claim';
const ACK_ROUTE = /^\/api\/workforce-audit\/external-scanner\/jobs\/([^/]+)\/acknowledge$/;
const FAIL_ROUTE = /^\/api\/workforce-audit\/external-scanner\/jobs\/([^/]+)\/fail$/;

export function createExternalScanJobDeliveryHandler({ registry, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.claimExternalScanJobs !== 'function') throw new TypeError('A scan-job-aware evidence registry is required.');

  function matches(pathname) { return pathname === CLAIM_ROUTE || ACK_ROUTE.test(pathname) || FAIL_ROUTE.test(pathname); }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method !== 'POST') return notFound(res, requestId);
    try {
      const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
      const burst = rateLimiter?.consume?.(`external-scanner-delivery:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst);
      }
      const decision = rateLimiter?.consume?.(`external-scanner-delivery:${client}`, 'write');
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision);
      }
      const body = await readBody(req, 65_536);
      let data;
      if (url.pathname === CLAIM_ROUTE) data = registry.claimExternalScanJobs(body, req.headers);
      else {
        const ack = url.pathname.match(ACK_ROUTE);
        const failed = url.pathname.match(FAIL_ROUTE);
        if (ack) data = registry.acknowledgeExternalScanJob(decodePathSegment(ack[1], 'jobId'), body, req.headers);
        else if (failed) data = registry.failExternalScanJob(decodePathSegment(failed[1], 'jobId'), body, req.headers);
        else return notFound(res, requestId);
      }
      record(securityTelemetry, {
        type: url.pathname === CLAIM_ROUTE ? 'external_scan.jobs_claimed' : url.pathname.endsWith('/acknowledge') ? 'external_scan.job_delivered' : 'external_scan.job_delivery_failed',
        severity: url.pathname.endsWith('/fail') ? 'high' : 'info', outcome: 'success', requestId,
        method: req.method, route: url.pathname,
        details: url.pathname === CLAIM_ROUTE
          ? { providerId: data.providerId, claimed: data.jobs.length }
          : { jobId: data.jobId, providerId: data.providerId, state: data.state }
      });
      return sendJson(res, 200, { success: true, data, meta: { requestId } }, requestId);
    } catch (error) {
      if (error instanceof ExternalScanAuthenticationError) {
        record(securityTelemetry, { type: 'external_scan.delivery_authentication_failed', severity: 'critical', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.details?.reason ?? error.code } });
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, { 'www-authenticate': 'HMAC realm="workforce-audit-external-scanner-delivery"' });
      }
      if (error instanceof RateLimitStoreError) return unavailable(res, requestId, error);
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, { success: false, error: 'The external scan delivery queue is busy. Retry the request.', code: 'EXTERNAL_SCAN_JOB_BUSY', details: error.details, meta: { requestId } }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, 'EXTERNAL_SCAN_JOB_STORE_UNAVAILABLE');
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError
          || error instanceof ExternalScanJobStoreError) {
        record(securityTelemetry, { type: 'external_scan.delivery_denied', severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.code } });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, claimRoute: CLAIM_ROUTE });
}

async function readBody(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Scanner delivery requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Scanner delivery request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function decodePathSegment(value, field) {
  try { return decodeURIComponent(value); }
  catch { throw new EvidenceValidationError(`The ${field} path segment contains invalid percent encoding.`, { field }); }
}
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision) { return sendJson(res, 429, { success: false, error: 'The external scanner delivery rate limit has been exceeded.', code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: { requestId } }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('External scanner delivery telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'External scanner delivery route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
