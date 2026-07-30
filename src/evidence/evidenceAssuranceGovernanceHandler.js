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
  EvidenceAssuranceGovernanceIntegrityError,
  EvidenceAssuranceGovernanceStoreError
} from './evidenceAssuranceGovernanceStore.js';

const STATUS_ROUTE = '/api/workforce-audit/assurance-governance/status';
const REPORT_ROUTE = '/api/workforce-audit/assurance-governance/report';
const BUNDLE_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/assurance-bundles$/;
const REQUESTS_ROUTE = /^\/api\/workforce-audit\/evidence\/([^/]+)\/assurance-requests$/;
const REQUEST_ROUTE = /^\/api\/workforce-audit\/assurance-requests\/([^/]+)$/;
const APPROVE_ROUTE = /^\/api\/workforce-audit\/assurance-requests\/([^/]+)\/approve$/;
const REJECT_ROUTE = /^\/api\/workforce-audit\/assurance-requests\/([^/]+)\/reject$/;
const REVOKE_ROUTE = /^\/api\/workforce-audit\/assurance-requests\/([^/]+)\/revoke$/;
const SEAL_ROUTE = /^\/api\/workforce-audit\/assurance-requests\/([^/]+)\/seal$/;
const CLAIM_ROUTE = '/api/workforce-audit/assurance-recipient/bundles/claim';
const ACK_ROUTE = /^\/api\/workforce-audit\/assurance-recipient\/bundles\/([^/]+)\/acknowledge$/;

export function createEvidenceAssuranceGovernanceHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.requestAssuranceBundle !== 'function') throw new TypeError('An assurance-governance-aware registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === REPORT_ROUTE || pathname === CLAIM_ROUTE
      || BUNDLE_ROUTE.test(pathname) || REQUESTS_ROUTE.test(pathname) || REQUEST_ROUTE.test(pathname)
      || APPROVE_ROUTE.test(pathname) || REJECT_ROUTE.test(pathname) || REVOKE_ROUTE.test(pathname)
      || SEAL_ROUTE.test(pathname) || ACK_ROUTE.test(pathname);
  }

  async function handle(req, res, requestId = randomUUID()) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === CLAIM_ROUTE || ACK_ROUTE.test(url.pathname)) return handleRecipient(req, res, url, requestId);
    return handleGovernance(req, res, url, requestId);
  }

  async function handleRecipient(req, res, url, requestId) {
    if (req.method !== 'POST') return notFound(res, requestId);
    try {
      const client = rateLimiter?.clientAddress?.(req) ?? 'unknown';
      const decision = rateLimiter?.consume?.(`assurance-recipient:${client}`, 'write');
      if (decision) { applyRateHeaders(res, rateLimiter, decision); if (!decision.allowed) return rateLimited(res, requestId, decision); }
      const body = await readBody(req, 65_536);
      const data = url.pathname === CLAIM_ROUTE
        ? registry.claimAssuranceBundles(body, req.headers)
        : registry.acknowledgeAssuranceBundle(decodeSegment(url.pathname.match(ACK_ROUTE)[1], 'bundleId'), body, req.headers);
      record(securityTelemetry, { type: url.pathname === CLAIM_ROUTE ? 'assurance_governance.recipient_claim' : 'assurance_governance.delivered', severity: 'info', outcome: 'success', requestId, route: url.pathname, details: url.pathname === CLAIM_ROUTE ? { recipientId: data.recipientId, bundles: data.bundles.length } : { bundleId: data.bundleId, recipientId: data.recipientId } });
      return sendJson(res, 200, { success: true, data, meta: { requestId } }, requestId);
    } catch (error) { return knownError(error, res, requestId, null); }
  }

  async function handleGovernance(req, res, url, requestId) {
    const client = rateLimiter?.clientAddress?.(req) ?? 'unknown';
    let principal = null;
    try {
      const burst = rateLimiter?.consume?.(`client:${client}`, 'burst');
      if (burst) { applyRateHeaders(res, rateLimiter, burst); if (!burst.allowed) return rateLimited(res, requestId, burst); }
      principal = await authenticationGateway.authenticate(req);
      authenticationGateway.authorise(principal, permissionFor(req.method, url.pathname));
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:assurance-governance`, req.method === 'GET' ? 'read' : 'privileged');
      if (decision) { applyRateHeaders(res, rateLimiter, decision); if (!decision.allowed) return rateLimited(res, requestId, decision); }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') return sendJson(res, 200, { success: true, data: registry.assuranceGovernanceStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      if (url.pathname === REPORT_ROUTE && req.method === 'GET') return sendJson(res, 200, { success: true, data: registry.assuranceGovernanceReport(principal.tenantId), meta: meta(requestId, principal) }, requestId);

      let match = url.pathname.match(BUNDLE_ROUTE) ?? url.pathname.match(REQUESTS_ROUTE);
      if (match) {
        const evidenceId = decodeSegment(match[1], 'evidenceId');
        if (req.method === 'GET') {
          const data = url.pathname.endsWith('/assurance-bundles')
            ? registry.assuranceBundles(principal.tenantId, evidenceId, { limit: positiveInteger(url.searchParams.get('limit'), 100, 5000) })
            : registry.assuranceRequests(principal.tenantId, evidenceId, { state: url.searchParams.get('state'), limit: positiveInteger(url.searchParams.get('limit'), 100, 5000) });
          return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
        if (req.method === 'POST') {
          const input = await readJson(req, 32_768, new Set(['version', 'recipientId', 'purpose', 'purposeCode', 'legalBasis', 'residencyZone', 'confirmation']));
          const data = registry.requestAssuranceBundle(principal.tenantId, evidenceId, input, { actor: principal.subject, role: principal.role });
          record(securityTelemetry, { type: 'assurance_governance.requested', severity: 'high', outcome: 'success', requestId, subject: principal.subject, tenantId: principal.tenantId, route: url.pathname, details: { requestId: data.requestId, evidenceId, recipientId: data.recipientId, purposeCode: data.purposeCode, residencyZone: data.residencyZone } });
          return sendJson(res, 202, { success: true, data, meta: meta(requestId, principal) }, requestId);
        }
      }

      match = url.pathname.match(APPROVE_ROUTE);
      if (match && req.method === 'POST') {
        const requestIdValue = decodeSegment(match[1], 'requestId');
        const input = await readJson(req, 8192, new Set(['confirmation']));
        exactConfirmation(input.confirmation, `APPROVE ASSURANCE ${requestIdValue}`);
        const data = registry.approveAssuranceRequest(principal.tenantId, requestIdValue, { actor: principal.subject, role: principal.role });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      match = url.pathname.match(SEAL_ROUTE);
      if (match && req.method === 'POST') {
        const requestIdValue = decodeSegment(match[1], 'requestId');
        const input = await readJson(req, 8192, new Set(['confirmation']));
        exactConfirmation(input.confirmation, `SEAL ASSURANCE ${requestIdValue}`);
        const data = registry.sealApprovedRequest(principal.tenantId, requestIdValue);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      match = url.pathname.match(REJECT_ROUTE) ?? url.pathname.match(REVOKE_ROUTE);
      if (match && req.method === 'POST') {
        const requestIdValue = decodeSegment(match[1], 'requestId');
        const input = await readJson(req, 8192, new Set(['confirmation', 'reason']));
        const revoke = REVOKE_ROUTE.test(url.pathname);
        exactConfirmation(input.confirmation, `${revoke ? 'REVOKE' : 'REJECT'} ASSURANCE ${requestIdValue}`);
        const data = revoke
          ? registry.revokeAssuranceRequest(principal.tenantId, requestIdValue, input, { actor: principal.subject })
          : registry.rejectAssuranceRequest(principal.tenantId, requestIdValue, input, { actor: principal.subject });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      match = url.pathname.match(REQUEST_ROUTE);
      if (match && req.method === 'GET') return sendJson(res, 200, { success: true, data: registry.assuranceRequest(principal.tenantId, decodeSegment(match[1], 'requestId')), meta: meta(requestId, principal) }, requestId);
      return notFound(res, requestId);
    } catch (error) {
      if (error instanceof AuthenticationError) {
        let failed;
        try { failed = rateLimiter?.consume?.(`authentication:${client}`, 'authFailure'); if (failed) applyRateHeaders(res, rateLimiter, failed); }
        catch (storeError) { if (storeError instanceof RateLimitStoreError) return unavailable(res, requestId, storeError, principal); throw storeError; }
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed);
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      return knownError(error, res, requestId, principal);
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, claimRoute: CLAIM_ROUTE });
}

function permissionFor(method, pathname) {
  if (method === 'GET') return 'governance:read';
  if (REJECT_ROUTE.test(pathname) || REVOKE_ROUTE.test(pathname)) return 'privileged:revoke';
  return 'evidence:export';
}
function knownError(error, res, requestId, principal) {
  if (error instanceof SecurityControlBusyError) return sendJson(res, 423, { success: false, error: 'The assurance governance boundary is busy.', code: 'EVIDENCE_ASSURANCE_GOVERNANCE_BUSY', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '1' });
  if (error instanceof SecurityControlUnavailableError || error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
  if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError || error instanceof EvidenceNotFoundError || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError || error instanceof EvidenceAssuranceGovernanceIntegrityError || error instanceof EvidenceAssuranceGovernanceStoreError) return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: meta(requestId, principal) }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
  throw error;
}
async function readBody(req, maximumBytes) { const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase(); if (contentType !== 'application/json') throw new EvidenceValidationError('Assurance governance requests require Content-Type application/json.', { field: 'content-type' }); const chunks = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > maximumBytes) throw new EvidenceValidationError('The assurance governance request body is too large.', { field: 'body' }); chunks.push(chunk); } return Buffer.concat(chunks); }
async function readJson(req, maximumBytes, allowed) { const bytes = await readBody(req, maximumBytes); let input; try { input = JSON.parse(bytes.toString('utf8') || '{}'); } catch { throw new EvidenceValidationError('The assurance governance request must contain valid JSON.', { field: 'body' }); } if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('The assurance governance request body must be an object.', { field: 'body' }); for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Unsupported assurance governance field ${key}.`, { field: key }); return input; }
function exactConfirmation(value, expected) { if (value !== expected) throw new EvidenceValidationError(`confirmation must be exactly ${expected}.`, { field: 'confirmation' }); }
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} contains invalid percent encoding.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = limiter?.headers?.(decision) ?? {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision) { return sendJson(res, 429, { success: false, error: 'The assurance governance rate limit has been exceeded.', code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal) { return sendJson(res, 503, { success: false, error: error.message, code: error.code ?? 'EVIDENCE_ASSURANCE_GOVERNANCE_STORE_UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Assurance governance telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Assurance governance route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, extra = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...extra }); res.end(JSON.stringify(payload)); }
