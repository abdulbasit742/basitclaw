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
} from '../evidence/evidenceRegistry.js';
import { AuditSamplingValidationError } from './auditSamplingEngine.js';
import { AuditSamplingIntegrityError, AuditSamplingStoreError } from './auditSamplingStore.js';

const STATUS_ROUTE = '/api/workforce-audit/sampling-plans/status';
const PLANS_ROUTE = '/api/workforce-audit/sampling-plans';
const PLAN_ROUTE = /^\/api\/workforce-audit\/sampling-plans\/([^/]+)$/;
const APPROVE_ROUTE = /^\/api\/workforce-audit\/sampling-plans\/([^/]+)\/approve$/;
const CANCEL_ROUTE = /^\/api\/workforce-audit\/sampling-plans\/([^/]+)\/cancel$/;
const VERIFY_ROUTE = /^\/api\/workforce-audit\/sampling-plans\/([^/]+)\/verify$/;

export function createAuditSamplingHandler({ registry, authenticationGateway, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.createSamplingPlan !== 'function') throw new TypeError('An audit-sampling-aware registry is required.');
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') throw new TypeError('An authentication gateway is required.');

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === PLANS_ROUTE || PLAN_ROUTE.test(pathname)
      || APPROVE_ROUTE.test(pathname) || CANCEL_ROUTE.test(pathname) || VERIFY_ROUTE.test(pathname);
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
      const sensitive = APPROVE_ROUTE.test(url.pathname) || CANCEL_ROUTE.test(url.pathname) || VERIFY_ROUTE.test(url.pathname);
      const decision = rateLimiter?.consume?.(
        `credential:${principal.keyId ?? principal.subject}:audit-sampling`,
        sensitive ? 'sensitive' : req.method === 'POST' ? 'write' : 'read'
      );
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The audit sampling request rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, { success: true, data: registry.auditSamplingStatus(principal.tenantId), meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === PLANS_ROUTE && req.method === 'GET') {
        const data = registry.samplingPlans(principal.tenantId, {
          engagementId: optionalText(url.searchParams.get('engagementId')),
          status: optionalText(url.searchParams.get('status')),
          limit: positiveInteger(url.searchParams.get('limit'), 100, 500)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === PLANS_ROUTE && req.method === 'POST') {
        const input = await readJson(req, 5_000_000, new Set([
          'engagementId', 'objective', 'rationale', 'evidenceId', 'evidenceVersion', 'idempotencyKey',
          'method', 'sampleSize', 'strata', 'population'
        ]));
        const data = registry.createSamplingPlan(principal.tenantId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: data.duplicate ? 'audit_sampling.plan_duplicate' : 'audit_sampling.plan_created',
          severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: {
            planId: data.plan.planId,
            engagementId: data.plan.engagementId,
            evidenceId: data.plan.evidenceId,
            populationCount: data.plan.populationCount,
            method: data.plan.method,
            sourceReferencesPublic: false
          }
        });
        return sendJson(res, data.duplicate ? 200 : 201, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const approveMatch = url.pathname.match(APPROVE_ROUTE);
      if (approveMatch && req.method === 'POST') {
        const planId = decodeSegment(approveMatch[1], 'planId');
        const input = await readJson(req, 8_192, new Set(['confirmation']));
        const data = registry.approveSamplingPlan(principal.tenantId, planId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: data.duplicate ? 'audit_sampling.approval_duplicate' : 'audit_sampling.plan_approved',
          severity: 'info', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { planId, selectionHash: data.plan.selection?.selectionHash, selectedItems: data.plan.selection?.selected?.length }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const cancelMatch = url.pathname.match(CANCEL_ROUTE);
      if (cancelMatch && req.method === 'POST') {
        const planId = decodeSegment(cancelMatch[1], 'planId');
        const input = await readJson(req, 16_384, new Set(['confirmation', 'reason']));
        const data = registry.cancelSamplingPlan(principal.tenantId, planId, input, { actor: principal.subject });
        record(securityTelemetry, {
          type: data.duplicate ? 'audit_sampling.cancellation_duplicate' : 'audit_sampling.plan_cancelled',
          severity: 'high', outcome: data.duplicate ? 'duplicate' : 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId, method: req.method, route: url.pathname,
          details: { planId, reasonCode: 'governed_cancellation' }
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const verifyMatch = url.pathname.match(VERIFY_ROUTE);
      if (verifyMatch && req.method === 'POST') {
        const planId = decodeSegment(verifyMatch[1], 'planId');
        const data = registry.verifySamplingPlan(principal.tenantId, planId);
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }

      const planMatch = url.pathname.match(PLAN_ROUTE);
      if (planMatch && req.method === 'GET') {
        const planId = decodeSegment(planMatch[1], 'planId');
        return sendJson(res, 200, { success: true, data: registry.samplingPlan(principal.tenantId, planId), meta: meta(requestId, principal) }, requestId);
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
          method: req.method, route: url.pathname, details: { reason: error.code, boundary: 'audit-sampling' }
        });
        if (failed && !failed.allowed) return rateLimited(res, requestId, failed, 'Too many failed authentication attempts.');
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'www-authenticate': challenge(authenticationGateway.mode) });
      }
      if (error instanceof AuthorizationError) {
        record(securityTelemetry, {
          type: 'authorization.denied', severity: 'high', outcome: 'denied', requestId,
          subject: principal?.subject, tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { reason: error.details?.reason, boundary: 'audit-sampling' }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: meta(requestId, principal) }, requestId);
      }
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') return unavailable(res, requestId, error, principal);
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false, error: 'The audit sampling boundary is busy. Retry the request.', code: 'AUDIT_SAMPLING_BUSY',
          details: error.details, meta: meta(requestId, principal)
        }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) return unavailable(res, requestId, error, principal, 'AUDIT_SAMPLING_STORE_UNAVAILABLE');
      if (error instanceof AuditSamplingValidationError || error instanceof AuditSamplingIntegrityError || error instanceof AuditSamplingStoreError
          || error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError || error instanceof EvidenceConflictError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError) {
        record(securityTelemetry, {
          type: 'audit_sampling.request_denied',
          severity: error instanceof EvidenceIntegrityError || error instanceof AuditSamplingIntegrityError ? 'critical' : 'high',
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

function permissionFor(method, pathname) {
  if (method === 'GET') return 'audit:read';
  if (pathname === PLANS_ROUTE && method === 'POST') return 'fieldwork:write';
  if ((APPROVE_ROUTE.test(pathname) || CANCEL_ROUTE.test(pathname) || VERIFY_ROUTE.test(pathname)) && method === 'POST') return 'engagement:write';
  return 'audit:read';
}
async function readJson(req, maximumBytes, allowed) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('Audit sampling requests require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Audit sampling request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Audit sampling request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new EvidenceValidationError('Audit sampling request body must be an object.', { field: 'body' });
  for (const key of Object.keys(input)) if (!allowed.has(key)) throw new EvidenceValidationError(`Audit sampling request contains unsupported field ${key}.`, { field: key });
  return input;
}
function decodeSegment(value, field) { try { return decodeURIComponent(value); } catch { throw new EvidenceValidationError(`${field} is not valid percent-encoded text.`, { field }); } }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function optionalText(value) { const text = String(value ?? '').trim(); return text || null; }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challenge(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Audit sampling telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Audit sampling route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
