import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from '../evidence/evidenceRegistry.js';
import {
  RegulatoryCaseApprovalError,
  RegulatoryCaseIntegrityError,
  RegulatoryCaseStoreError
} from './regulatoryCaseStore.js';

const BASE = '/api/workforce-audit/regulatory-cases';
const STATUS = `${BASE}/status`;
const VERIFY = `${BASE}/verify`;
const ITEM = /^\/api\/workforce-audit\/regulatory-cases\/([^/]+)$/;
const EVENTS = /^\/api\/workforce-audit\/regulatory-cases\/([^/]+)\/events$/;
const ACTION = /^\/api\/workforce-audit\/regulatory-cases\/([^/]+)\/(evidence|submit-response|approve-response|close|cancel)$/;

export function createRegulatoryCaseHandler({ store, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!store || typeof store.createCase !== 'function') throw new TypeError('A regulatory case store is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === BASE || pathname === STATUS || pathname === VERIFY
      || ITEM.test(pathname) || EVENTS.test(pathname) || ACTION.test(pathname);
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
      const permission = permissionFor(req.method, url.pathname);
      authenticationGateway.authorise(principal, permission);
      const policy = permission === 'regulatory:case:approve' ? 'sensitive' : req.method === 'GET' ? 'read' : 'write';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:regulatory-cases`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The regulatory case request rate limit has been exceeded.');
      }

      if (url.pathname === STATUS && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: store.tenantStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === VERIFY && req.method === 'POST') {
        const data = store.verifyTenant(principal.tenantId);
        record(securityTelemetry, 'regulatory_case.verified', principal, req, url, requestId, { checkedCases: data.checkedCases, checkedEvents: data.checkedEvents });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === BASE && req.method === 'GET') {
        const data = store.list(principal.tenantId, {
          state: url.searchParams.get('state'),
          priority: url.searchParams.get('priority'),
          limit: positiveInteger(url.searchParams.get('limit'), 200, 2000)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === BASE && req.method === 'POST') {
        const input = await readJson(req, 131072);
        const data = store.createCase(principal.tenantId, input, { actor: principal.subject });
        record(securityTelemetry, data.duplicate ? 'regulatory_case.duplicate' : 'regulatory_case.created', principal, req, url, requestId, { caseId: data.case.caseId, authority: data.case.authority, dueAt: data.case.dueAt, evidenceCount: data.case.evidence.length });
        return sendJson(res, data.duplicate ? 200 : 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const action = url.pathname.match(ACTION);
      if (action && req.method === 'POST') {
        const caseId = decodeSegment(action[1], 'caseId');
        const input = await readJson(req, action[2] === 'evidence' ? 65536 : 16384);
        const method = action[2] === 'evidence' ? 'addEvidence'
          : action[2] === 'submit-response' ? 'submitResponse'
            : action[2] === 'approve-response' ? 'approveResponse'
              : action[2] === 'close' ? 'closeCase' : 'cancelCase';
        const data = store[method](principal.tenantId, caseId, input, { actor: principal.subject });
        record(securityTelemetry, `regulatory_case.${action[2].replace('-', '_')}`, principal, req, url, requestId, { caseId, state: data.state, deadlineState: data.deadlineState });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const eventMatch = url.pathname.match(EVENTS);
      if (eventMatch && req.method === 'GET') {
        const caseId = decodeSegment(eventMatch[1], 'caseId');
        const data = store.events(principal.tenantId, caseId, { limit: positiveInteger(url.searchParams.get('limit'), 500, 5000) });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const item = url.pathname.match(ITEM);
      if (item && req.method === 'GET') {
        const data = store.get(principal.tenantId, decodeSegment(item[1], 'caseId'));
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
        record(securityTelemetry, 'authentication.failed', principal, req, url, requestId, { boundary: 'regulatory-cases', reason: error.code }, 'high', 'denied');
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, 'authorization.denied', principal, req, url, requestId, { boundary: 'regulatory-cases', reason: error.details?.reason }, 'high', 'denied');
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
      if (error instanceof SecurityControlBusyError) return sendJson(res, 423, { success: false, error: 'The regulatory case register is busy. Retry the request.', code: 'REGULATORY_CASE_BUSY', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'REGULATORY_CASE_STORE_UNAVAILABLE');
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError || error instanceof RegulatoryCaseApprovalError || error instanceof RegulatoryCaseIntegrityError || error instanceof RegulatoryCaseStoreError) {
        record(securityTelemetry, 'regulatory_case.denied', principal, req, url, requestId, { reason: error.code }, error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError ? 'critical' : 'high', 'denied');
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, baseRoute: BASE });
}

function permissionFor(method, pathname) {
  if (method === 'POST' && (pathname === VERIFY || /\/(approve-response|close|cancel)$/.test(pathname))) return 'regulatory:case:approve';
  return 'regulatory:case';
}
async function readJson(req, maximumBytes) { const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase(); if (contentType !== 'application/json') throw new EvidenceValidationError('Regulatory case requests require Content-Type application/json.', { field: 'content-type' }); const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > maximumBytes) throw new EvidenceValidationError('The regulatory case request body is too large.', { field: 'body' }); chunks.push(chunk); } try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { throw new EvidenceValidationError('The regulatory case request body must be valid JSON.', { field: 'body' }); } }
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, type, principal, req, url, requestId, details, severity = 'info', outcome = 'success') { try { telemetry?.record?.({ type, severity, outcome, requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details }); } catch (error) { console.error('Regulatory case telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Regulatory case route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
