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
  EvidenceDisclosureIntegrityError,
  EvidenceDisclosureStoreError
} from './evidenceDisclosureStore.js';

const COLLECTION_ROUTE = '/api/workforce-audit/evidence-disclosures';
const STATUS_ROUTE = '/api/workforce-audit/evidence-disclosures/status';
const ITEM_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)$/;
const DOWNLOAD_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/download$/;
const VERIFY_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/verify$/;
const REVOKE_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/revoke$/;

export function createEvidenceDisclosureHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.createEvidenceDisclosure !== 'function') throw new TypeError('A disclosure-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === COLLECTION_ROUTE || pathname === STATUS_ROUTE
      || ITEM_ROUTE.test(pathname) || DOWNLOAD_ROUTE.test(pathname)
      || VERIFY_ROUTE.test(pathname) || REVOKE_ROUTE.test(pathname);
  }

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
      authenticationGateway.authorise(principal, 'evidence:export');
      const policy = req.method === 'GET' ? 'read' : 'sensitive';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-disclosures`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence disclosure rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.evidenceDisclosureStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === COLLECTION_ROUTE && req.method === 'GET') {
        const data = registry.listEvidenceDisclosures(principal.tenantId, { limit: positiveInteger(url.searchParams.get('limit'), 100, 1000) });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === COLLECTION_ROUTE && req.method === 'POST') {
        const input = await readJson(req, 256_000);
        const data = registry.createEvidenceDisclosure(principal.tenantId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: data.duplicate ? 'evidence_disclosure.duplicate' : 'evidence_disclosure.created',
          severity: 'high', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { packageId: data.disclosure.packageId, itemCount: data.disclosure.itemCount, recipientKeyId: data.disclosure.recipientKeyId }
        });
        return sendJson(res, data.duplicate ? 200 : 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const download = url.pathname.match(DOWNLOAD_ROUTE);
      if (download && req.method === 'GET') {
        const packageId = decodeSegment(download[1], 'packageId');
        const data = registry.downloadEvidenceDisclosure(principal.tenantId, packageId);
        record(securityTelemetry, {
          type: 'evidence_disclosure.downloaded', severity: 'high', outcome: 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { packageId, downloadCount: data.disclosure.downloadCount, maximumDownloads: data.disclosure.maximumDownloads }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId, {
          'content-disposition': `attachment; filename="${packageId}.json"`
        });
      }
      const verify = url.pathname.match(VERIFY_ROUTE);
      if (verify && req.method === 'POST') {
        const packageId = decodeSegment(verify[1], 'packageId');
        const data = registry.verifyEvidenceDisclosure(principal.tenantId, packageId);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      const revoke = url.pathname.match(REVOKE_ROUTE);
      if (revoke && req.method === 'POST') {
        const packageId = decodeSegment(revoke[1], 'packageId');
        const input = await readJson(req, 16_384);
        const data = registry.revokeEvidenceDisclosure(principal.tenantId, packageId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: 'evidence_disclosure.revoked', severity: 'critical', outcome: 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { packageId, revokedAt: data.revokedAt }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      const item = url.pathname.match(ITEM_ROUTE);
      if (item && req.method === 'GET') {
        const packageId = decodeSegment(item[1], 'packageId');
        const data = registry.evidenceDisclosureMetadata(principal.tenantId, packageId);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
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
          details: { reason: error.code, boundary: 'evidence-disclosures' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': challengeHeader(authenticationGateway.mode)
        });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, {
          type: 'authorization.denied', severity: 'critical', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { permission: 'evidence:export', boundary: 'evidence-disclosures' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      return handleKnownError(error, res, requestId, principal);
    }
  }

  return Object.freeze({ matches, handle, collectionRoute: COLLECTION_ROUTE, statusRoute: STATUS_ROUTE });
}

function handleKnownError(error, res, requestId, principal) {
  if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
    return unavailable(res, requestId, error, principal);
  }
  if (error instanceof SecurityControlBusyError) {
    return sendJson(res, 423, {
      success: false, error: 'The evidence disclosure boundary is busy. Retry the request.',
      code: 'EVIDENCE_DISCLOSURE_BUSY', details: error.details, meta: meta(requestId, principal)
    }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
  }
  if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE');
  if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
      || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
      || error instanceof EvidenceStoreError || error instanceof EvidenceDisclosureStoreError
      || error instanceof EvidenceDisclosureIntegrityError) {
    return sendJson(res, error.statusCode ?? 500, {
      success: false, error: error.message, code: error.code,
      details: error.details, meta: meta(requestId, principal)
    }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
  }
  throw error;
}

async function readJson(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Evidence disclosure requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Evidence disclosure request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Evidence disclosure request body must be valid JSON.', { field: 'body' }); }
}
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challengeHeader(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence disclosure telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Evidence disclosure route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
