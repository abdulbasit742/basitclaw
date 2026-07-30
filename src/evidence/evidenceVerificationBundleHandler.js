import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import { sha256 } from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  EvidenceVerificationBundleError,
  EvidenceVerificationBundleIntegrityError
} from './evidenceVerificationBundle.js';

const STATUS_ROUTE = '/api/workforce-audit/evidence-verification-bundles/status';
const VERIFY_ROUTE = '/api/workforce-audit/evidence-verification-bundles/verify';
const CREATE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/verification-bundles$/;

export function createEvidenceVerificationBundleHandler({
  service,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!service || typeof service.create !== 'function') throw new TypeError('A verification-bundle service is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === VERIFY_ROUTE || CREATE_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The request burst limit has been exceeded.');
      }
      principal = await authenticationGateway.authenticate(req);
      const createMatch = url.pathname.match(CREATE_ROUTE);
      const permission = createMatch ? 'evidence:preserve' : 'governance:read';
      authenticationGateway.authorise(principal, permission);
      const policy = createMatch ? 'sensitive' : 'read';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-bundles`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The verification-bundle request rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          data: service.health(),
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (url.pathname === VERIFY_ROUTE && req.method === 'POST') {
        const input = await readJson(req, 2_000_000, new Set(['bundle', 'allowExpired']));
        const data = service.verify(input.bundle, { allowExpired: Boolean(input.allowExpired) });
        record(securityTelemetry, {
          type: 'evidence.verification_bundle_verified', severity: 'info', outcome: 'success',
          requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: { bundleId: data.bundleId, evidenceId: data.evidenceId }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (createMatch && req.method === 'POST') {
        const evidenceId = decodeSegment(createMatch[1], 'evidenceId');
        const input = await readJson(req, 32_768, new Set([
          'version', 'profile', 'recipientRef', 'purpose', 'confirmation', 'expiresAt'
        ]));
        const data = service.create(principal.tenantId, evidenceId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: 'evidence.verification_bundle_exported', severity: 'high', outcome: 'success',
          requestId, subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: {
            bundleId: data.summary.bundleId,
            evidenceId,
            version: data.summary.evidenceVersion,
            profile: data.summary.profile,
            recipientDigest: sha256(data.summary.recipientRef)
          }
        });
        return sendJson(res, 201, { success: true, data, meta: meta(requestId, principal) }, requestId, {
          'content-disposition': `attachment; filename="${data.summary.bundleId}.json"`
        });
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
          details: { reason: error.code, boundary: 'evidence-verification-bundles' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, {
          success: false, error: error.message, code: error.code, meta: { requestId }
        }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, {
          type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId,
          method: req.method, route: url.pathname,
          details: { reason: error.details?.reason, boundary: 'evidence-verification-bundles' }
        });
        return sendJson(res, 403, {
          success: false, error: error.message, code: error.code, meta: meta(requestId, principal)
        }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return unavailable(res, requestId, error, principal);
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError || error instanceof EvidenceVerificationBundleError
          || error instanceof EvidenceVerificationBundleIntegrityError) {
        const status = error.statusCode ?? (error instanceof EvidenceValidationError ? 400 : 500);
        record(securityTelemetry, {
          type: 'evidence.verification_bundle_denied',
          severity: status >= 500 || error instanceof EvidenceIntegrityError ? 'critical' : 'high',
          outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId,
          method: req.method, route: url.pathname, details: { reason: error.code }
        });
        return sendJson(res, status, {
          success: false,
          error: error.message,
          code: error.code,
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, status === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, verifyRoute: VERIFY_ROUTE });
}

async function readJson(req, maximumBytes, allowedFields) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Verification-bundle requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Verification-bundle request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Verification-bundle request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('Verification-bundle request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) {
    if (!allowedFields.has(key)) throw new EvidenceValidationError(`Verification-bundle request contains unsupported field ${key}.`, { field: key });
  }
  return input;
}

function decodeSegment(value, field) {
  try { return decodeURIComponent(value); }
  catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); }
}
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal) { return sendJson(res, 503, { success: false, error: error.message, code: error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Verification-bundle route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Verification-bundle telemetry failed', error); } }
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
