import { randomUUID } from 'node:crypto';
import { AuthenticationError, AuthorizationError } from '../security/accessControl.js';
import { OidcUnavailableError } from '../security/oidcAuthenticator.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  EvidenceDisclosureAuthenticationError,
  EvidenceDisclosureIntegrityError,
  EvidenceDisclosureStoreError
} from './evidenceDisclosureStore.js';

const STATUS_ROUTE = '/api/workforce-audit/evidence-disclosures/status';
const REPORT_ROUTE = '/api/workforce-audit/evidence-disclosures/report';
const EVIDENCE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/disclosures$/;
const DISCLOSURE_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)$/;
const APPROVE_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/approve$/;
const REVOKE_ROUTE = /^\/api\/workforce-audit\/evidence-disclosures\/([^/]+)\/revoke$/;
const CLAIM_ROUTE = '/api/workforce-audit/evidence-disclosure-recipient/claim';
const ACK_ROUTE = /^\/api\/workforce-audit\/evidence-disclosure-recipient\/([^/]+)\/acknowledge$/;

export function createEvidenceDisclosureHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.requestEvidenceDisclosure !== 'function') throw new TypeError('A disclosure-aware evidence registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === REPORT_ROUTE || pathname === CLAIM_ROUTE
      || EVIDENCE_ROUTE.test(pathname) || DISCLOSURE_ROUTE.test(pathname)
      || APPROVE_ROUTE.test(pathname) || REVOKE_ROUTE.test(pathname) || ACK_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === CLAIM_ROUTE || ACK_ROUTE.test(url.pathname)) {
      return handleRecipient(req, res, url, requestId);
    }
    return handleGovernance(req, res, url, requestId);
  }

  async function handleRecipient(req, res, url, requestId) {
    if (req.method !== 'POST') return notFound(res, requestId);
    try {
      const client = rateLimiter?.clientAddress?.(req) ?? 'unknown';
      const burst = rateLimiter?.consume?.(`evidence-disclosure-recipient:${client}`, 'burst');
      if (burst) {
        applyRateHeaders(res, rateLimiter, burst);
        if (!burst.allowed) return rateLimited(res, requestId, burst, 'The recipient request burst limit has been exceeded.');
      }
      const decision = rateLimiter?.consume?.(`evidence-disclosure-recipient:${client}`, 'write');
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The recipient request rate limit has been exceeded.');
      }
      const body = await readBody(req, 65_536);
      let data;
      if (url.pathname === CLAIM_ROUTE) data = registry.claimEvidenceDisclosures(body, req.headers);
      else {
        const match = url.pathname.match(ACK_ROUTE);
        if (!match) return notFound(res, requestId);
        data = registry.acknowledgeEvidenceDisclosure(decodeSegment(match[1], 'disclosureId'), body, req.headers);
      }
      record(securityTelemetry, {
        type: url.pathname === CLAIM_ROUTE ? 'evidence_disclosure.recipient_claimed' : 'evidence_disclosure.acknowledged',
        severity: 'info', outcome: 'success', requestId, method: req.method, route: url.pathname,
        details: url.pathname === CLAIM_ROUTE
          ? { recipientId: data.recipientId, tenantId: data.tenantId, claimed: data.jobs.length }
          : { disclosureId: data.disclosureId, recipientId: data.recipientId, state: data.state }
      });
      return sendJson(res, 200, { success: true, data, meta: { requestId } }, requestId);
    } catch (error) {
      if (error instanceof EvidenceDisclosureAuthenticationError) {
        record(securityTelemetry, { type: 'evidence_disclosure.recipient_authentication_failed', severity: 'critical', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.details?.reason ?? error.code } });
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, { 'www-authenticate': 'HMAC realm="workforce-audit-evidence-disclosure"' });
      }
      return handleKnownError(error, res, requestId, null);
    }
  }

  async function handleGovernance(req, res, url, requestId) {
    const client = rateLimiter?.clientAddress?.(req) ?? 'unknown';
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
      const policy = req.method === 'GET' ? 'read' : 'write';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:evidence-disclosure`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The disclosure governance rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.health().disclosures, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === REPORT_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.evidenceDisclosureReport(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      let match = url.pathname.match(EVIDENCE_ROUTE);
      if (match) {
        const evidenceId = decodeSegment(match[1], 'evidenceId');
        if (req.method === 'GET') {
          registry.get(principal.tenantId, evidenceId);
          const data = registry.evidenceDisclosures(principal.tenantId, {
            evidenceId,
            state: url.searchParams.get('state'),
            limit: positiveInteger(url.searchParams.get('limit'), 100, 5000)
          });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method === 'POST') {
          const input = await readJson(req, 16_384, new Set(['version', 'recipientId', 'residencyZone', 'purpose', 'expiresAt']));
          const data = registry.requestEvidenceDisclosure(principal.tenantId, evidenceId, input, { actor: principal.subject, role: principal.role });
          record(securityTelemetry, { type: 'evidence_disclosure.requested', severity: 'high', outcome: 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname, details: { disclosureId: data.disclosureId, evidenceId, recipientId: data.recipientId, residencyZone: data.residencyZone } });
          return sendJson(res, 202, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
      }
      match = url.pathname.match(APPROVE_ROUTE);
      if (match && req.method === 'POST') {
        const disclosureId = decodeSegment(match[1], 'disclosureId');
        const input = await readJson(req, 8_192, new Set(['confirmation']));
        if (input.confirmation !== `APPROVE DISCLOSURE ${disclosureId}`) throw new EvidenceValidationError(`confirmation must be exactly APPROVE DISCLOSURE ${disclosureId}.`, { field: 'confirmation' });
        const data = registry.approveEvidenceDisclosure(principal.tenantId, disclosureId, { actor: principal.subject, role: principal.role });
        record(securityTelemetry, { type: data.state === 'sealed' ? 'evidence_disclosure.sealed' : 'evidence_disclosure.approved', severity: 'high', outcome: 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname, details: { disclosureId, approvals: data.approvals.length, state: data.state } });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      match = url.pathname.match(REVOKE_ROUTE);
      if (match && req.method === 'POST') {
        const disclosureId = decodeSegment(match[1], 'disclosureId');
        const input = await readJson(req, 8_192, new Set(['confirmation', 'reason']));
        if (input.confirmation !== `REVOKE DISCLOSURE ${disclosureId}`) throw new EvidenceValidationError(`confirmation must be exactly REVOKE DISCLOSURE ${disclosureId}.`, { field: 'confirmation' });
        const data = registry.revokeEvidenceDisclosure(principal.tenantId, disclosureId, input, { actor: principal.subject });
        record(securityTelemetry, { type: 'evidence_disclosure.revoked', severity: 'critical', outcome: 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname, details: { disclosureId } });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      match = url.pathname.match(DISCLOSURE_ROUTE);
      if (match && req.method === 'GET') {
        const data = registry.evidenceDisclosure(principal.tenantId, decodeSegment(match[1], 'disclosureId'));
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
        record(securityTelemetry, { type: 'authentication.failed', severity: 'high', outcome: 'denied', requestId, method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'evidence-disclosure' } });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, { type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId, subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname, details: { reason: error.details?.reason, boundary: 'evidence-disclosure' } });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      return handleKnownError(error, res, requestId, principal);
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, claimRoute: CLAIM_ROUTE });
}

function permissionFor(method, pathname) {
  if (method === 'GET') return 'governance:read';
  if (APPROVE_ROUTE.test(pathname)) return 'evidence:disclose:approve';
  if (REVOKE_ROUTE.test(pathname)) return 'evidence:disclose:revoke';
  return 'evidence:disclose:request';
}

function handleKnownError(error, res, requestId, principal) {
  if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
  if (error instanceof SecurityControlBusyError) return sendJson(res, 423, { success: false, error: 'The evidence disclosure boundary is busy. Retry the request.', code: 'EVIDENCE_DISCLOSURE_BUSY', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
  if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'EVIDENCE_DISCLOSURE_STORE_UNAVAILABLE');
  if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError || error instanceof EvidenceConflictError
      || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError
      || error instanceof EvidenceDisclosureIntegrityError || error instanceof EvidenceDisclosureStoreError) {
    return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
  }
  throw error;
}

async function readBody(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Evidence disclosure requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Evidence disclosure request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req, maximumBytes, allowed) {
  const body = await readBody(req, maximumBytes);
  let input;
  try { input = JSON.parse(body.toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Evidence disclosure request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('Evidence disclosure request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Evidence disclosure request contains unsupported field ${key}.`, { field: key });
  return input;
}

function decodeSegment(value, field) {
  try { return decodeURIComponent(value); }
  catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); }
}
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = limiter?.headers?.(decision) ?? {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Evidence disclosure telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Evidence disclosure route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
