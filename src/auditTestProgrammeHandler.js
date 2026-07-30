import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from './security/accessControl.js';
import { OidcUnavailableError } from './security/oidcAuthenticator.js';
import { RateLimitStoreError } from './security/sharedRateLimiter.js';
import { NotFoundError, ValidationError } from './services/workforceAuditService.js';

const COLLECTION_ROUTE = '/api/workforce-audit/test-programmes';
const CREATE_ROUTE = /^\/api\/workforce-audit\/engagements\/([^/]+)\/test-programmes$/;
const PROGRAMME_ROUTE = /^\/api\/workforce-audit\/test-programmes\/([^/]+)$/;
const VERIFY_ROUTE = /^\/api\/workforce-audit\/test-programmes\/([^/]+)\/verify$/;
const RESULT_ROUTE = /^\/api\/workforce-audit\/test-programmes\/([^/]+)\/samples\/([^/]+)\/results$/;
const SUBMIT_ROUTE = /^\/api\/workforce-audit\/test-programmes\/([^/]+)\/submit$/;
const REVIEW_ROUTE = /^\/api\/workforce-audit\/test-programmes\/([^/]+)\/review$/;

export function createAuditTestProgrammeHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.forTenant !== 'function') throw new TypeError('A workforce-audit registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === COLLECTION_ROUTE
      || CREATE_ROUTE.test(pathname)
      || PROGRAMME_ROUTE.test(pathname)
      || VERIFY_ROUTE.test(pathname)
      || RESULT_ROUTE.test(pathname)
      || SUBMIT_ROUTE.test(pathname)
      || REVIEW_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const clientAddress = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${clientAddress}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The client request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      const permission = permissionFor(req.method, url.pathname);
      authenticationGateway.authorise(principal, permission);
      const policy = url.pathname.endsWith('/review') ? 'sensitive' : req.method === 'GET' ? 'read' : 'write';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:audit-test-programmes`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The audit test-programme request rate limit has been exceeded.');
      }
      const service = registry.forTenant(principal.tenantId);
      const context = { actor: principal.subject };
      const meta = { requestId, tenantId: principal.tenantId, keyId: principal.keyId ?? null };

      if (req.method === 'GET' && url.pathname === COLLECTION_ROUTE) {
        const data = service.getTestProgrammes({
          engagementId: url.searchParams.get('engagementId'),
          status: url.searchParams.get('status')
        });
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }

      const createMatch = url.pathname.match(CREATE_ROUTE);
      if (req.method === 'POST' && createMatch) {
        const engagementId = decodeSegment(createMatch[1], 'engagementId');
        const data = service.createTestProgramme(engagementId, await readJson(req, 5_000_000), context);
        record(securityTelemetry, principal, req, url, requestId, 'audit_test_programme.created', 'success', {
          programmeId: data.id,
          engagementId,
          populationSize: data.sampling.populationSize,
          sampleSize: data.sampling.sampleSize
        });
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }

      const verifyMatch = url.pathname.match(VERIFY_ROUTE);
      if (req.method === 'GET' && verifyMatch) {
        const data = service.verifyTestProgramme(decodeSegment(verifyMatch[1], 'programmeId'));
        return sendJson(res, data.valid ? 200 : 409, { success: data.valid, data, meta }, requestId);
      }

      const resultMatch = url.pathname.match(RESULT_ROUTE);
      if (req.method === 'POST' && resultMatch) {
        const programmeId = decodeSegment(resultMatch[1], 'programmeId');
        const sampleId = decodeSegment(resultMatch[2], 'sampleId');
        const data = service.recordTestResult(programmeId, sampleId, await readJson(req, 1_000_000), context);
        record(securityTelemetry, principal, req, url, requestId, 'audit_test_sample.recorded', 'success', {
          programmeId,
          sampleId,
          attempt: data.attempts.length,
          outcome: data.attempts.at(-1).overallOutcome
        });
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }

      const submitMatch = url.pathname.match(SUBMIT_ROUTE);
      if (req.method === 'POST' && submitMatch) {
        const programmeId = decodeSegment(submitMatch[1], 'programmeId');
        const data = service.submitTestProgramme(programmeId, await readJson(req, 100_000), context);
        record(securityTelemetry, principal, req, url, requestId, 'audit_test_programme.submitted', 'success', { programmeId });
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }

      const reviewMatch = url.pathname.match(REVIEW_ROUTE);
      if (req.method === 'POST' && reviewMatch) {
        const programmeId = decodeSegment(reviewMatch[1], 'programmeId');
        const data = service.reviewTestProgramme(programmeId, await readJson(req, 100_000), context);
        record(securityTelemetry, principal, req, url, requestId, 'audit_test_programme.finalised', 'success', {
          programmeId,
          conclusion: data.review.conclusion
        });
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }

      const programmeMatch = url.pathname.match(PROGRAMME_ROUTE);
      if (req.method === 'GET' && programmeMatch) {
        const data = service.getTestProgramme(decodeSegment(programmeMatch[1], 'programmeId'));
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }

      return notFound(res, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed;
        try {
          failed = rateLimiter?.consume?.(`authentication:${clientAddress}`, 'authFailure');
          if (failed) applyRateHeaders(res, rateLimiter, failed);
        } catch (storeError) {
          if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError, principal);
          throw storeError;
        }
        record(securityTelemetry, principal, req, url, requestId, 'authentication.failed', 'denied', { boundary: 'audit-test-programmes', reason: error.code });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': challenge(authenticationGateway.mode)
        });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, principal, req, url, requestId, 'authorization.denied', 'denied', { boundary: 'audit-test-programmes', permission: error.details?.permission });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: responseMeta(requestId, principal) }, requestId);
      }
      if (error instanceof ValidationError) {
        return sendJson(res, 400, { success: false, error: error.message, code: error.code, details: error.details, meta: responseMeta(requestId, principal) }, requestId);
      }
      if (error instanceof NotFoundError) {
        return sendJson(res, 404, { success: false, error: error.message, code: error.code, meta: responseMeta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return unavailable(res, requestId, error, principal);
      }
      if (error?.code === 'PERSISTENCE_UNAVAILABLE' || error?.code === 'PERSISTENCE_FENCE_REJECTED') {
        return sendJson(res, 503, {
          success: false,
          error: 'The audit test-programme change could not be committed to durable storage.',
          code: error.code,
          details: error.details,
          meta: responseMeta(requestId, principal)
        }, requestId, { 'retry-after': '30' });
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, collectionRoute: COLLECTION_ROUTE });
}

function permissionFor(method, pathname) {
  if (method === 'GET') return pathname.endsWith('/verify') ? 'governance:read' : 'audit:read';
  if (pathname.endsWith('/review')) return 'engagement:write';
  return 'fieldwork:write';
}

async function readJson(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new ValidationError('Audit test-programme requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new ValidationError('Audit test-programme request body is too large.', { field: 'body', maximumBytes });
    chunks.push(chunk);
  }
  let value;
  try { value = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new ValidationError('Audit test-programme request body must be valid JSON.', { field: 'body' }); }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ValidationError('Audit test-programme request body must be an object.', { field: 'body' });
  return value;
}

function decodeSegment(value, field) {
  try { return decodeURIComponent(value); }
  catch { throw new ValidationError(`${field} has invalid percent encoding.`, { field }); }
}

function applyRateHeaders(res, limiter, decision) {
  const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {};
  for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
}

function rateLimited(res, requestId, decision, message) {
  return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, {
    'retry-after': String(decision.retryAfterSeconds ?? 1)
  });
}

function unavailable(res, requestId, error, principal) {
  return sendJson(res, 503, {
    success: false,
    error: error.message,
    code: error.code ?? 'UNAVAILABLE',
    details: error.details,
    meta: responseMeta(requestId, principal)
  }, requestId, { 'retry-after': '30' });
}

function challenge(mode) {
  return mode === 'api-key'
    ? 'ApiKey realm="workforce-audit"'
    : mode === 'oidc'
      ? 'Bearer realm="workforce-audit"'
      : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"';
}

function responseMeta(requestId, principal) {
  return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null };
}

function record(telemetry, principal, req, url, requestId, type, outcome, details) {
  try {
    telemetry?.record?.({
      type,
      severity: outcome === 'denied' ? 'high' : 'info',
      outcome,
      requestId,
      subject: principal?.subject,
      tenantId: principal?.tenantId,
      method: req.method,
      route: url.pathname,
      details
    });
  } catch (error) {
    console.error('Audit test-programme telemetry failed', error);
  }
}

function notFound(res, requestId) {
  return sendJson(res, 404, { success: false, error: 'Audit test-programme route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId);
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
