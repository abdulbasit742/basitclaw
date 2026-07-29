import { randomUUID } from 'node:crypto';
import { SecurityControlBusyError, SecurityControlUnavailableError } from '../security/fileMutex.js';
import { RateLimitStoreError } from '../security/sharedRateLimiter.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  ExternalScanAuthenticationError,
  ExternalScanStoreError
} from './externalScanAttestationRegistry.js';

const ROUTE = '/api/workforce-audit/external-scanner/attestations';

export function createExternalScanCallbackHandler({ registry, rateLimiter = null, securityTelemetry = null } = {}) {
  if (!registry || typeof registry.recordExternalScanAttestation !== 'function') throw new TypeError('An external-scan-aware evidence registry is required.');

  function matches(pathname) { return pathname === ROUTE; }

  async function handle(req, res, requestId = randomUUID()) {
    if (req.method !== 'POST') return sendJson(res, 404, { success: false, error: 'External scanner route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId);
    try {
      const client = typeof rateLimiter?.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
      if (typeof rateLimiter?.consume === 'function') {
        const decision = rateLimiter.consume(`external-scanner:${client}`, 'write');
        applyRateHeaders(res, rateLimiter, decision);
        if (!decision.allowed) {
          record(securityTelemetry, { type: 'external_scan.rate_limited', severity: 'high', outcome: 'denied', requestId, method: req.method, route: ROUTE, details: { policy: decision.policy } });
          return sendJson(res, 429, { success: false, error: 'The external scanner callback rate limit has been exceeded.', code: 'RATE_LIMITED', details: decision, meta: { requestId } }, requestId, { 'retry-after': String(decision.retryAfterSeconds ?? 1) });
        }
      }
      const body = await readBody(req, 262_144);
      const result = registry.recordExternalScanAttestation(body, req.headers);
      record(securityTelemetry, {
        type: result.duplicate ? 'external_scan.attestation_duplicate' : 'external_scan.attestation_accepted',
        severity: result.attestation.verdict === 'clean' ? 'info' : result.attestation.verdict === 'error' ? 'high' : 'critical',
        outcome: result.duplicate ? 'duplicate' : 'success',
        requestId,
        method: req.method,
        route: ROUTE,
        details: {
          evidenceId: result.attestation.evidenceId,
          version: result.attestation.version,
          providerId: result.attestation.providerId,
          verdict: result.attestation.verdict,
          attestationId: result.attestation.attestationId
        }
      });
      return sendJson(res, result.duplicate ? 200 : 202, { success: true, data: result, meta: { requestId } }, requestId);
    } catch (error) {
      if (error instanceof ExternalScanAuthenticationError) {
        record(securityTelemetry, { type: 'external_scan.authentication_failed', severity: 'critical', outcome: 'denied', requestId, method: req.method, route: ROUTE, details: { reason: error.details?.reason ?? error.code } });
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, { 'www-authenticate': 'HMAC realm="workforce-audit-external-scanner"' });
      }
      if (error instanceof SecurityControlBusyError) {
        return sendJson(res, 423, {
          success: false,
          error: 'The external scanner release-policy boundary is busy. Retry the callback.',
          code: 'EXTERNAL_SCAN_POLICY_BUSY',
          details: error.details,
          meta: { requestId }
        }, requestId, { 'retry-after': String(Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000))) });
      }
      if (error instanceof SecurityControlUnavailableError) {
        return sendJson(res, 503, {
          success: false,
          error: 'The external scanner release-policy boundary is unavailable.',
          code: 'EXTERNAL_SCAN_POLICY_UNAVAILABLE',
          details: error.details,
          meta: { requestId }
        }, requestId, { 'retry-after': '30' });
      }
      if (error instanceof RateLimitStoreError) return sendJson(res, 503, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, { 'retry-after': '30' });
      if (error instanceof EvidenceValidationError || error instanceof EvidenceConflictError
          || error instanceof EvidenceIntegrityError || error instanceof EvidenceStoreError
          || error instanceof ExternalScanStoreError) {
        record(securityTelemetry, {
          type: error instanceof EvidenceStoreError ? 'external_scan.store_unavailable' : 'external_scan.attestation_denied',
          severity: error instanceof EvidenceStoreError || error instanceof EvidenceIntegrityError ? 'critical' : 'high',
          outcome: 'denied', requestId, method: req.method, route: ROUTE, details: { reason: error.code }
        });
        return sendJson(res, error.statusCode ?? 500, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, error.statusCode === 503 ? { 'retry-after': '30' } : {});
      }
      throw error;
    }
  }

  return Object.freeze({ matches, handle, route: ROUTE });
}

async function readBody(req, maximumBytes) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new EvidenceValidationError('External scanner callbacks require Content-Type application/json.', { field: 'content-type' });
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maximumBytes) throw new EvidenceValidationError(`External scanner callback exceeds ${maximumBytes} bytes.`, { field: 'body' });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
function applyRateHeaders(res, limiter, decision) { const headers = typeof limiter.headers === 'function' ? limiter.headers(decision) : {}; for (const [name, value] of Object.entries(headers)) res.setHeader(name, value); }
function record(telemetry, input) { try { telemetry?.record?.(input); } catch (error) { console.error('External scanner telemetry record failed', error); } }
function sendJson(res, status, payload, requestId, additionalHeaders = {}) { res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-request-id': requestId, ...additionalHeaders }); res.end(JSON.stringify(payload)); }
