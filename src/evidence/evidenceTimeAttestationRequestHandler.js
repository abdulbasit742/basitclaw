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
import {
  EvidenceNotaryRequestAuthenticationError,
  EvidenceNotaryRequestStoreError
} from './evidenceTimeAttestationRequestOutbox.js';

const STATUS_ROUTE = '/api/workforce-audit/evidence-notary/requests/status';
const CLAIM_ROUTE = '/api/workforce-audit/evidence-notary/requests/claim';
const VERIFY_ROUTE = '/api/workforce-audit/evidence-notary/requests/verify';
const ARCHIVE_REQUESTS_ROUTE = /^\/api\/workforce-audit\/evidence-preservation\/([^/]+)\/notary-requests$/;
const ACK_ROUTE = /^\/api\/workforce-audit\/evidence-notary\/requests\/([^/]+)\/acknowledge$/;
const FAIL_ROUTE = /^\/api\/workforce-audit\/evidence-notary\/requests\/([^/]+)\/fail$/;
const REQUEUE_ROUTE = /^\/api\/workforce-audit\/evidence-notary\/requests\/([^/]+)\/requeue$/;
const QUEUE_FIELDS = new Set(['providerId', 'purpose', 'confirmation']);
const REQUEUE_FIELDS = new Set(['purpose', 'confirmation']);

export function createEvidenceTimeAttestationRequestHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.queueTimeAttestationRequest !== 'function') {
    throw new TypeError('A notary-request-aware evidence registry is required.');
  }
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') {
    throw new TypeError('An authentication gateway is required.');
  }

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === CLAIM_ROUTE || pathname === VERIFY_ROUTE
      || ARCHIVE_REQUESTS_ROUTE.test(pathname) || ACK_ROUTE.test(pathname)
      || FAIL_ROUTE.test(pathname) || REQUEUE_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === CLAIM_ROUTE || ACK_ROUTE.test(url.pathname) || FAIL_ROUTE.test(url.pathname)) {
      return handleAuthority(req, res, requestId, url);
    }
    return handleGovernance(req, res, requestId, url);
  }

  async function handleAuthority(req, res, requestId, url) {
    if (req.method !== 'POST') return notFound(res, requestId);
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    try {
      const burst = rateLimiter?.consume?.(`evidence-notary-request-authority:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The time-authority request burst limit has been exceeded.');
      }
      const decision = rateLimiter?.consume?.(`evidence-notary-request-authority:${client}`, 'write');
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The time-authority request rate limit has been exceeded.');
      }
      const input = await readJson(req, 32_768);
      let data;
      if (url.pathname === CLAIM_ROUTE) data = registry.claimTimeAttestationRequests(input);
      else {
        const acknowledged = url.pathname.match(ACK_ROUTE);
        const failed = url.pathname.match(FAIL_ROUTE);
        if (acknowledged) {
          data = registry.acknowledgeTimeAttestationRequest(decodeSegment(acknowledged[1], 'jobId'), input);
        } else if (failed) {
          data = registry.failTimeAttestationRequest(decodeSegment(failed[1], 'jobId'), input);
        } else return notFound(res, requestId);
      }
      const providerId = data.providerId ?? input.providerId;
      const providerDecision = rateLimiter?.consume?.(`evidence-notary-request-provider:${providerId}`, 'write');
      if (providerDecision) applyRateHeaders(res, rateLimiter, providerDecision);
      record(securityTelemetry, {
        type: url.pathname === CLAIM_ROUTE
          ? 'evidence_notary_request.claimed'
          : url.pathname.endsWith('/acknowledge')
            ? 'evidence_notary_request.acknowledged'
            : 'evidence_notary_request.failed',
        severity: url.pathname.endsWith('/fail') ? 'high' : 'info',
        outcome: 'success', requestId, method: req.method, route: url.pathname,
        details: url.pathname === CLAIM_ROUTE
          ? { providerId, claimed: data.jobs.length }
          : { providerId, jobId: data.jobId, state: data.state }
      });
      return sendJson(res, 200, { success: true, data, meta: { requestId } }, requestId);
    } catch (error) {
      if (error instanceof EvidenceNotaryRequestAuthenticationError) {
        record(securityTelemetry, {
          type: 'evidence_notary_request.authentication_failed', severity: 'critical', outcome: 'denied',
          requestId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason ?? error.code }
        });
        return sendJson(res, 401, {
          success: false, error: error.message, code: error.code,
          details: error.details, meta: { requestId }
        }, requestId, { 'www-authenticate': 'Signature realm="workforce-audit-evidence-notary-requests"' });
      }
      return handleKnownError(error, res, requestId, null);
    }
  }

  async function handleGovernance(req, res, requestId, url) {
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      const writing = req.method === 'POST' && url.pathname !== VERIFY_ROUTE;
      authenticationGateway.authorise(principal, writing ? 'evidence:notarize' : 'governance:read');
      const policy = writing ? 'sensitive' : req.method === 'POST' ? 'sensitive' : 'read';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-notary-requests`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence-notary request governance rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          data: registry.evidenceTimeAttestationRequestStatus(principal.tenantId),
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (url.pathname === VERIFY_ROUTE && req.method === 'POST') {
        const data = registry.verifyEvidenceTimeAttestationRequests(principal.tenantId);
        record(securityTelemetry, {
          type: 'evidence_notary_request.verified', severity: 'info', outcome: 'success',
          requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: { checkedJobs: data.checkedJobs, checkedEvents: data.checkedEvents }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      const archive = url.pathname.match(ARCHIVE_REQUESTS_ROUTE);
      if (archive) {
        const archiveId = decodeSegment(archive[1], 'archiveId');
        if (req.method === 'GET') {
          const data = registry.evidenceTimeAttestationRequests(principal.tenantId, archiveId, {
            providerId: url.searchParams.get('providerId'),
            limit: positiveInteger(url.searchParams.get('limit'), 500, 5000)
          });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method === 'POST') {
          const input = await readJson(req, 16_384, QUEUE_FIELDS);
          const data = registry.queueTimeAttestationRequest(principal.tenantId, archiveId, input, {
            actor: principal.subject
          });
          record(securityTelemetry, {
            type: data.alreadyAttested
              ? 'evidence_notary_request.already_attested'
              : data.duplicate ? 'evidence_notary_request.duplicate' : 'evidence_notary_request.queued',
            severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success',
            requestId, subject: principal.subject, tenantId: principal.tenantId,
            method: req.method, route: url.pathname,
            details: { archiveId, providerId: input.providerId, jobId: data.job?.jobId ?? null }
          });
          return sendJson(res, data.queued ? 202 : 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
      }
      const requeue = url.pathname.match(REQUEUE_ROUTE);
      if (requeue && req.method === 'POST') {
        const jobId = decodeSegment(requeue[1], 'jobId');
        const input = await readJson(req, 16_384, REQUEUE_FIELDS);
        const data = registry.requeueTimeAttestationRequest(principal.tenantId, jobId, input, {
          actor: principal.subject
        });
        record(securityTelemetry, {
          type: 'evidence_notary_request.requeued', severity: 'high', outcome: 'success',
          requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: { jobId, providerId: data.job.providerId }
        });
        return sendJson(res, 202, { success: true, data, meta: meta(requestId, principal) }, requestId);
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
        record(securityTelemetry, {
          type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId,
          method: req.method, route: url.pathname,
          details: { reason: error.code, boundary: 'evidence-notary-request-governance' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, {
          success: false, error: error.message, code: error.code, meta: { requestId }
        }, requestId, { 'www-authenticate': challengeHeader(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        return sendJson(res, 403, {
          success: false, error: error.message, code: error.code, meta: meta(requestId, principal)
        }, requestId);
      }
      return handleKnownError(error, res, requestId, principal);
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, claimRoute: CLAIM_ROUTE });
}

function handleKnownError(error, res, requestId, principal) {
  if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
    return unavailable(res, requestId, error, principal);
  }
  if (error instanceof SecurityControlBusyError) {
    return sendJson(res, 423, {
      success: false,
      error: 'The evidence-notary request boundary is busy. Retry the request.',
      code: 'EVIDENCE_NOTARY_REQUEST_BUSY',
      details: error.details,
      meta: meta(requestId, principal)
    }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
  }
  if (error instanceof SecurityControlUnavailableError) {
    return unavailable(res, requestId, error, principal, 'EVIDENCE_NOTARY_REQUEST_STORE_UNAVAILABLE');
  }
  if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
      || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
      || error instanceof EvidenceStoreError || error instanceof EvidenceNotaryRequestStoreError) {
    return sendJson(res, error.statusCode ?? 500, {
      success: false, error: error.message, code: error.code,
      details: error.details, meta: meta(requestId, principal)
    }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
  }
  throw error;
}

async function readJson(req, maximumBytes, allowedFields = null) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new EvidenceValidationError('Evidence-notary requests require Content-Type application/json.', { field: 'content-type' });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Evidence-notary request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Evidence-notary request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('Evidence-notary request body must be an object.', { field: 'body' });
  }
  if (allowedFields) {
    for (const key of Object.keys(input)) {
      if (!allowedFields.has(key)) throw new EvidenceValidationError(`Unsupported evidence-notary request field ${key}.`, { field: key });
    }
  }
  return input;
}

function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challengeHeader(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence-notary request telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Evidence-notary request route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
