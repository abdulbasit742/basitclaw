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
  EvidenceAssuranceBundleAuthenticationError,
  EvidenceAssuranceBundleStoreError
} from './evidenceAssuranceBundleStore.js';

const STATUS_ROUTE = '/api/workforce-audit/assurance-bundles/status';
const GOVERNANCE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/assurance-bundles$/;
const CLAIM_ROUTE = '/api/workforce-audit/assurance-recipient/bundles/claim';
const ACK_ROUTE = /^\/api\/workforce-audit\/assurance-recipient\/bundles\/([^/]+)\/acknowledge$/;

export function createEvidenceAssuranceBundleHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.createAssuranceBundle !== 'function') throw new TypeError('An assurance-bundle-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === CLAIM_ROUTE || GOVERNANCE_ROUTE.test(pathname) || ACK_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const recipientBoundary = url.pathname === CLAIM_ROUTE || ACK_ROUTE.test(url.pathname);
    try {
      if (recipientBoundary) return await handleRecipient(req, res, url, requestId);
      return await handleGovernance(req, res, url, requestId);
    } catch (error) {
      if (error instanceof EvidenceAssuranceBundleAuthenticationError) {
        record(securityTelemetry, { type: 'assurance_bundle.recipient_authentication_failed', severity: 'critical', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.details?.reason ?? error.code } });
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, { 'www-authenticate': 'HMAC realm="workforce-audit-assurance-recipient"' });
      }
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, { success: false, error: 'The assurance bundle boundary is busy. Retry the request.', code: 'EVIDENCE_ASSURANCE_BUNDLE_BUSY', details: error.details, meta: { requestId } }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError || error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return sendJson(res, 503, { success: false, error: error.message, code: error.code ?? 'EVIDENCE_ASSURANCE_BUNDLE_STORE_UNAVAILABLE', details: error.details, meta: { requestId } }, requestId, { 'retry-after': '30' });
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError || error instanceof EvidenceAssuranceBundleStoreError) {
        record(securityTelemetry, { type: 'assurance_bundle.request_denied', severity: error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError ? 'critical' : 'high', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.code } });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  async function handleGovernance(req, res, url, requestId) {
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
    if (burst) { applyRateHeaders(res, rateLimiter, burst); if (!burst.allowed) return rateLimited(res, requestId, burst); }
    let principal;
    try { principal = await authenticationGateway.authenticate(req); }
    catch (error) {
      if (!(error instanceof AuthenticationError)) throw error;
      let failed;
      try { failed = rateLimiter?.consume?.(`authentication:${client}`, 'authFailure'); if (failed) applyRateHeaders(res, rateLimiter, failed); }
      catch (storeError) { if (storeError instanceof RateLimitStoreError) throw storeError; throw storeError; }
      record(securityTelemetry, { type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'assurance-bundles' } });
      if (failed && !failed.allowed) return rateLimited(res, requestId, failed);
      return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
    }
    const permission = req.method === 'POST' ? 'evidence:export' : 'governance:read';
    try { authenticationGateway.authorise(principal, permission); }
    catch (error) {
      if (!(error instanceof AuthorizationError)) throw error;
      record(securityTelemetry, { type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId, subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname, details: { reason: error.details?.reason, boundary: 'assurance-bundles' } });
      return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
    }
    const policy = req.method === 'POST' ? 'privileged' : 'read';
    const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:assurance-bundles`, policy);
    if (decision) { applyRateHeaders(res, rateLimiter, decision); if (!decision.allowed) return rateLimited(res, requestId, decision); }

    if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
      return sendJson(res, 200, { success: true, data: registry.assuranceBundleStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
    }
    const match = url.pathname.match(GOVERNANCE_ROUTE);
    if (!match) return notFound(res, requestId);
    const evidenceId = decodeSegment(match[1], 'evidenceId');
    if (req.method === 'GET') {
      const data = registry.assuranceBundles(principal.tenantId, evidenceId, { limit: positiveInteger(url.searchParams.get('limit'), 100, 5000) });
      return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
    }
    if (req.method === 'POST') {
      const input = await readJson(req, 32_768, new Set(['version', 'recipientId', 'purpose', 'confirmation']));
      const data = registry.createAssuranceBundle(principal.tenantId, evidenceId, input, { actor: principal.subject });
      record(securityTelemetry, { type: data.duplicate ? 'assurance_bundle.duplicate' : 'assurance_bundle.queued', severity: 'high', outcome: data.duplicate ? 'duplicate' : 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname, details: { bundleId: data.bundle.bundleId, evidenceId, version: data.bundle.evidenceVersion, recipientId: data.bundle.recipientId } });
      return sendJson(res, data.duplicate ? 200 : 202, { success: true, data, meta: meta(requestId, principal) }, requestId);
    }
    return notFound(res, requestId);
  }

  async function handleRecipient(req, res, url, requestId) {
    if (req.method !== 'POST') return notFound(res, requestId);
    const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    const decision = rateLimiter?.consume?.(`assurance-recipient:${client}`, 'write');
    if (decision) { applyRateHeaders(res, rateLimiter, decision); if (!decision.allowed) return rateLimited(res, requestId, decision); }
    const body = await readBody(req, 65_536);
    let data;
    if (url.pathname === CLAIM_ROUTE) data = registry.claimAssuranceBundles(body, req.headers);
    else {
      const match = url.pathname.match(ACK_ROUTE);
      if (!match) return notFound(res, requestId);
      data = registry.acknowledgeAssuranceBundle(decodeSegment(match[1], 'bundleId'), body, req.headers);
    }
    record(securityTelemetry, { type: url.pathname === CLAIM_ROUTE ? 'assurance_bundle.claimed' : 'assurance_bundle.delivered', severity: 'info', outcome: 'success', requestId, method: req.method, route: url.pathname, details: url.pathname === CLAIM_ROUTE ? { recipientId: data.recipientId, claimed: data.jobs.length } : { bundleId: data.bundleId, recipientId: data.recipientId } });
    return sendJson(res, 200, { success: true, data, meta: { requestId } }, requestId);
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, claimRoute: CLAIM_ROUTE });
}

async function readJson(req, maximumBytes, allowed) { const bytes = await readBody(req, maximumBytes); let input; try { input = JSON.parse(bytes.toString('utf8') || '{}'); } catch { throw new EvidenceValidationError('The assurance bundle request must contain valid JSON.', { field: 'body' }); } if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('The assurance bundle request body must be an object.', { field: 'body' }); for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Unsupported assurance bundle field ${key}.`, { field: key }); return input; }
async function readBody(req, maximumBytes) { const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase(); if (contentType !== 'application/json') throw new EvidenceValidationError('Assurance bundle requests require Content-Type application/json.', { field: 'content-type' }); const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > maximumBytes) throw new EvidenceValidationError('The assurance bundle request body is too large.', { field: 'body' }); chunks.push(chunk); } return Buffer.concat(chunks); }
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision) { return sendJson(res, 429, { success: false, error: 'The assurance bundle request rate limit has been exceeded.', code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Assurance bundle telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Assurance bundle route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, extra = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...extra }); res.end(JSON.stringify(payload)); }
