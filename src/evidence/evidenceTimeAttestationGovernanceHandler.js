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
  EvidenceTimeAttestationGovernanceIntegrityError,
  EvidenceTimeAttestationGovernanceStoreError
} from './evidenceTimeAttestationGovernanceStore.js';

const STATUS_ROUTE = '/api/workforce-audit/evidence-notary/governance/status';
const EVENTS_ROUTE = '/api/workforce-audit/evidence-notary/governance/events';
const VERIFY_ROUTE = '/api/workforce-audit/evidence-notary/governance/verify';
const EVENT_FIELDS = new Set([
  'eventType', 'archiveId', 'attestationId', 'providerId', 'keyId', 'replacementAttestationId',
  'effectiveAt', 'retroactive', 'reasonCode', 'reason', 'confirmation'
]);

export function createEvidenceTimeAttestationGovernanceHandler({
  registry,
  authenticationGateway,
  rateLimiter = null,
  securityTelemetry = null
} = {}) {
  if (!registry || typeof registry.recordTimeAttestationGovernanceEvent !== 'function') {
    throw new TypeError('A time-attestation-governance-aware evidence registry is required.');
  }
  if (!authenticationGateway || typeof authenticationGateway.authenticate !== 'function') {
    throw new TypeError('An authentication gateway is required.');
  }

  function matches(pathname) {
    return pathname === STATUS_ROUTE || pathname === EVENTS_ROUTE || pathname === VERIFY_ROUTE;
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
      const write = req.method === 'POST' && url.pathname === EVENTS_ROUTE;
      authenticationGateway.authorise(principal, write ? 'evidence:notary-govern' : 'governance:read');
      const policy = write || (req.method === 'POST' && url.pathname === VERIFY_ROUTE) ? 'sensitive' : 'read';
      const decision = rateLimiter?.consume?.(`credential:${principal.keyId ?? principal.subject}:notary-governance`, policy);
      if (decision) {
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) return rateLimited(res, requestId, decision, 'The notary-governance rate limit has been exceeded.');
      }

      if (url.pathname === STATUS_ROUTE && req.method === 'GET') {
        return sendJson(res, 200, {
          success: true,
          data: registry.evidenceTimeAttestationGovernanceStatus(principal.tenantId),
          meta: meta(requestId, principal)
        }, requestId);
      }
      if (url.pathname === EVENTS_ROUTE && req.method === 'GET') {
        const data = registry.evidenceTimeAttestationGovernanceEvents(principal.tenantId, {
          eventType: optionalQuery(url, 'eventType'),
          attestationId: optionalQuery(url, 'attestationId'),
          providerId: optionalQuery(url, 'providerId'),
          keyId: optionalQuery(url, 'keyId'),
          limit: positiveInteger(url.searchParams.get('limit'), 500, 5000)
        });
        return sendJson(res, 200, { success: true, data, meta: meta(requestId, principal) }, requestId);
      }
      if (url.pathname === EVENTS_ROUTE && req.method === 'POST') {
        const input = await readJson(req, 16_384, EVENT_FIELDS);
        const data = registry.recordTimeAttestationGovernanceEvent(principal.tenantId, input, {
          actor: principal.subject
        });
        record(securityTelemetry, {
          type: data.duplicate ? 'evidence_time_attestation_governance.duplicate' : 'evidence_time_attestation_governance.recorded',
          severity: data.event.reasonCode.includes('compromise') ? 'critical' : 'high',
          outcome: data.duplicate ? 'duplicate' : 'success',
          requestId,
          subject: principal.subject,
          tenantId: principal.tenantId,
          method: req.method,
          route: url.pathname,
          details: {
            eventId: data.event.eventId,
            eventType: data.event.eventType,
            attestationId: data.event.attestationId,
            providerId: data.event.providerId,
            keyId: data.event.keyId,
            effectiveAt: data.event.effectiveAt,
            retroactive: data.event.retroactive
          }
        });
        return sendJson(res, data.duplicate ? 200 : 201, {
          success: true, data, meta: meta(requestId, principal)
        }, requestId);
      }
      if (url.pathname === VERIFY_ROUTE && req.method === 'POST') {
        const data = registry.verifyEvidenceTimeAttestationGovernance(principal.tenantId);
        record(securityTelemetry, {
          type: 'evidence_time_attestation_governance.verified',
          severity: 'info', outcome: 'success', requestId,
          subject: principal.subject, tenantId: principal.tenantId,
          method: req.method, route: url.pathname,
          details: { checkedEvents: data.checkedEvents, headSequence: data.headSequence }
        });
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
          details: { reason: error.code, boundary: 'evidence-notary-governance-journal' }
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
      if (error instanceof RateLimitStoreError || error instanceof OidcUnavailableError || error?.code === 'OIDC_UNAVAILABLE') {
        return unavailable(res, requestId, error, principal);
      }
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false,
          error: 'The time-attestation governance journal is busy. Retry the request.',
          code: 'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_BUSY',
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, {
          'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000)))
        });
      }
      if (error instanceof SecurityControlUnavailableError) {
        return unavailable(res, requestId, error, principal, 'EVIDENCE_TIME_ATTESTATION_GOVERNANCE_STORE_UNAVAILABLE');
      }
      if (error instanceof EvidenceValidationError || error instanceof EvidenceNotFoundError
          || error instanceof EvidenceConflictError || error instanceof EvidenceIntegrityError
          || error instanceof EvidenceStoreError || error instanceof EvidenceTimeAttestationGovernanceStoreError
          || error instanceof EvidenceTimeAttestationGovernanceIntegrityError) {
        return sendJson(res, error.statusCode ?? 500, {
          success: false,
          error: error.message,
          code: error.code,
          details: error.details,
          meta: meta(requestId, principal)
        }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, statusRoute: STATUS_ROUTE, eventsRoute: EVENTS_ROUTE });
}

async function readJson(req, maximumBytes, allowedFields) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new EvidenceValidationError('Time-attestation governance requests require Content-Type application/json.', {
      field: 'content-type'
    });
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError('Time-attestation governance request body is too large.', { field: 'body' });
    chunks.push(chunk);
  }
  let input;
  try { input = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch { throw new EvidenceValidationError('Time-attestation governance request body must be valid JSON.', { field: 'body' }); }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('Time-attestation governance request body must be an object.', { field: 'body' });
  }
  for (const field of Object.keys(input)) {
    if (!allowedFields.has(field)) {
      throw new EvidenceValidationError(`Time-attestation governance request contains unsupported field ${field}.`, {
        field
      });
    }
  }
  return input;
}

function optionalQuery(url, name) { const value = url.searchParams.get(name); return value === null || value === '' ? null : value; }
function positiveInteger(value, fallback, maximum) { if (value === null) return fallback; const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < 1) throw new EvidenceValidationError('limit must be a positive integer.', { field: 'limit' }); return Math.min(parsed, maximum); }
function meta(requestId, principal) { return { requestId, tenantId: principal?.tenantId ?? null, keyId: principal?.keyId ?? null }; }
function challengeHeader(mode) { return mode === 'api-key' ? 'ApiKey realm="workforce-audit"' : mode === 'oidc' ? 'Bearer realm="workforce-audit"' : 'Bearer realm="workforce-audit", ApiKey realm="workforce-audit"'; }
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter?.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function rateLimited(res, requestId, decision, message) { return sendJson(res, 429, { success: false, error: message, code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) }); }
function unavailable(res, requestId, error, principal, code = null) { return sendJson(res, 503, { success: false, error: error.message, code: code ?? error.code ?? 'UNAVAILABLE', details: error.details, meta: meta(requestId, principal) }, requestId, { 'retry-after': '30' }); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('Time-attestation governance telemetry failed', error); } }
function notFound(res, requestId) { return sendJson(res, 404, { success: false, error: 'Time-attestation governance route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId); }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
