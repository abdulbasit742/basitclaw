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
import { EvidenceDisclosureIntegrityError, EvidenceDisclosureStoreError } from './evidenceDisclosureBundleStore.js';

const STATUS_ROUTE = '/api/workforce-audit/disclosure-bundles/status';
const EVIDENCE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/disclosure-bundles$/;
const PACKAGE_ROUTE = /^\/api\/workforce-audit\/disclosure-bundles\/([^/]+)$/;
const VERIFY_ROUTE = /^\/api\/workforce-audit\/disclosure-bundles\/([^/]+)\/verify$/;

export function createEvidenceDisclosureHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.createDisclosureBundle !== 'function') throw new TypeError('A disclosure-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || EVIDENCE_ROUTE.test(pathname) || PACKAGE_ROUTE.test(pathname) || VERIFY_ROUTE.test(pathname);
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
      const isCreation = req.method === 'POST' && EVIDENCE_ROUTE.test(url.pathname);
      authenticationGateway.authorise(principal, isCreation ? 'evidence:disclose' : 'governance:read');
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-disclosures`, isCreation ? 'write' : 'read');
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The evidence disclosure request rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.disclosureStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }

      const evidenceMatch = url.pathname.match(EVIDENCE_ROUTE);
      if (evidenceMatch) {
        const evidenceId = decodeSegment(evidenceMatch[1], 'evidenceId');
        if (req.method === 'GET') {
          const data = registry.disclosureBundles(principal.tenantId, evidenceId, { limit: positiveInteger(url.searchParams.get('limit'), 100, 500) });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method === 'POST') {
          const input = await readJson(req, 65_536, new Set([
            'recipientId', 'idempotencyKey', 'purpose', 'expiresAt', 'versions', 'includeFilenames', 'confirmation'
          ]));
          const data = registry.createDisclosureBundle(principal.tenantId, evidenceId, input, { actor: principal.subject });
          record(securityTelemetry, {
            type: data.duplicate ? 'evidence.disclosure_duplicate' : 'evidence.disclosure_created',
            severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
            subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
            details: { bundleId: data.bundle.bundleId, evidenceId, recipientId: data.bundle.recipientId, versionCount: data.bundle.versionCount, rawEvidenceIncluded: false }
          });
          return sendJson(res, data.duplicate ? 200 : 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        return notFound(res, requestId);
      }

      const verifyMatch = url.pathname.match(VERIFY_ROUTE);
      if (verifyMatch && req.method === 'POST') {
        const bundleId = decodeSegment(verifyMatch[1], 'bundleId');
        const data = registry.verifyDisclosureBundle(principal.tenantId, bundleId);
        record(securityTelemetry, {
          type: 'evidence.disclosure_verified', severity: 'info', outcome: 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { bundleId, rawEvidenceIncluded: false }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const packageMatch = url.pathname.match(PACKAGE_ROUTE);
      if (packageMatch && req.method === 'GET') {
        const bundleId = decodeSegment(packageMatch[1], 'bundleId');
        const data = registry.disclosurePackage(principal.tenantId, bundleId);
        return sendJson(res, 200, data, requestId, {
          'content-disposition': `attachment; filename="${bundleId}.basitclaw-disclosure.json"`,
          'x-basitclaw-content-policy': 'metadata-only-recipient-encrypted'
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
          method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'evidence-disclosures' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, {
          type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason, boundary: 'evidence-disclosures' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false, error: 'The evidence disclosure boundary is busy. Retry the request.', code: 'EVIDENCE_DISCLOSURE_BUSY',
          details: error.details, meta: meta(requestId, principal)
        }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE');
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError || error instanceof EvidenceDisclosureStoreError
          || error instanceof EvidenceDisclosureIntegrityError) {
        record(securityTelemetry, {
          type: 'evidence.disclosure_denied', severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high',
          outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId,
          method: req.method, route: url.pathname, details: { reason: error.code }
        });
        return sendJson(res, error.statusCode ?? 500, {
          success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal)
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE });
}

async function readJson(req, maximumBytes, allowed) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Evidence disclosure requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Evidence disclosure request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Evidence disclosure request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('Evidence disclosure request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Evidence disclosure request contains unsupported field ${key}.`, { field: key });
  return input;
}
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} is not valid percent-encoded text.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence disclosure telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Evidence disclosure route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
