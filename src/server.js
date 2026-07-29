import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  CoordinationBusyError,
  CoordinationLostError,
  CoordinationUnavailableError
} from './coordination/fileLeaseCoordinator.js';
import { createRuntimeWorkforceAuditRegistry } from './coordination/coordinatedRegistry.js';
import { PersistenceError } from './persistence/encryptedSnapshotStore.js';
import { createResilienceSchedulerFromEnvironment } from './resilience/resilienceScheduler.js';
import { AuthenticationError, AuthorizationError, createAccessController } from './security/accessControl.js';
import {
  RateLimitError,
  classifyRequest,
  createAdaptiveRateLimiterFromEnvironment
} from './security/rateLimiter.js';
import { RateLimitStoreError } from './security/sharedRateLimiter.js';
import {
  SecurityArchiveError,
  SecurityArchiveIntegrityError,
  createSecurityEventArchiveFromEnvironment
} from './security/securityEventArchive.js';
import { createSecurityTelemetryFromEnvironment } from './security/securityTelemetry.js';
import {
  BackupError,
  BackupIntegrityError,
  BackupNotFoundError,
  RecoveryConflictError,
  ReplicaError,
  ReplicaIntegrityError,
  ReplicaNotFoundError
} from './services/workforceAuditRegistry.js';
import { NotFoundError, ValidationError } from './services/workforceAuditService.js';

const dashboardPath = fileURLToPath(new URL('../public/workforce-audit.html', import.meta.url));

export function createApp({
  registry = createRuntimeWorkforceAuditRegistry(),
  accessController = createAccessController(),
  resilienceScheduler = null,
  rateLimiter = createAdaptiveRateLimiterFromEnvironment(),
  securityArchive = createSecurityEventArchiveFromEnvironment(),
  securityTelemetry = createSecurityTelemetryFromEnvironment(process.env, { archive: securityArchive })
} = {}) {
  const scheduler = resilienceScheduler ?? createResilienceSchedulerFromEnvironment({
    registry,
    tenantIds: typeof accessController.tenantIds === 'function' ? accessController.tenantIds() : []
  });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const requestId = randomUUID();
    const clientAddress = typeof rateLimiter.clientAddress === 'function' ? rateLimiter.clientAddress(req) : 'unknown';
    let principal = null;
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        const persistence = registry.getPersistenceHealth();
        const credentials = typeof accessController.credentialHealth === 'function'
          ? accessController.credentialHealth()
          : { status: 'ready', total: accessController.principalCount ?? null, usable: accessController.principalCount ?? null };
        const rateLimiting = rateLimiter.health();
        const telemetry = securityTelemetry.summary();
        const replicaRequiredFailure = persistence.replicas?.required
          && (persistence.replicas.status !== 'ready' || persistence.replicas.readiness !== 'ready');
        const coordinationFailure = persistence.coordination?.enabled
          && persistence.coordination.status !== 'ready';
        const credentialFailure = credentials.status !== 'ready';
        const rateLimitFailure = rateLimiting.enabled && !['ready', 'disabled'].includes(rateLimiting.status);
        const archiveFailure = telemetry.archive?.required && telemetry.archive.status !== 'ready';
        const status = persistence.status === 'ready'
          && persistence.backups?.status === 'ready'
          && !replicaRequiredFailure
          && !coordinationFailure
          && !credentialFailure
          && !rateLimitFailure
          && !archiveFailure
          ? 200
          : 503;
        return sendJson(res, status, {
          success: status === 200,
          data: {
            status: status === 200 ? 'ok' : 'degraded',
            persistence,
            scheduler: scheduler.status(),
            apiSecurity: publicSecurityHealth({ credentials, rateLimiting, telemetry })
          },
          meta: { requestId }
        }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/dashboard/workforce-audit') {
        const html = await readFile(dashboardPath, 'utf8');
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'no-referrer'
        });
        return res.end(html);
      }

      if (!url.pathname.startsWith('/api/workforce-audit/')) {
        return sendJson(res, 404, { success: false, error: 'Route not found.', code: 'NOT_FOUND', meta: { requestId } }, requestId);
      }

      const burstDecision = rateLimiter.consume(`client:${clientAddress}`, 'burst');
      applyRateDecision(res, rateLimiter, burstDecision);
      if (!burstDecision.allowed) throw new RateLimitError('The client request burst limit has been exceeded.', burstDecision);

      try {
        principal = accessController.authenticate(req);
      } catch (error) {
        if (error instanceof AuthenticationError) {
          const failedDecision = rateLimiter.consume(`authentication:${clientAddress}`, 'authFailure');
          applyRateDecision(res, rateLimiter, failedDecision);
          safeRecordSecurityEvent(securityTelemetry, {
            type: 'authentication.failed',
            severity: error.code === 'UNAUTHENTICATED' ? 'warning' : 'high',
            outcome: 'denied',
            requestId,
            clientAddress,
            keyId: error.details?.keyId,
            method: req.method,
            route: url.pathname,
            details: { reason: error.details?.reason ?? error.code }
          });
          if (!failedDecision.allowed) throw new RateLimitError('Too many failed authentication attempts.', failedDecision);
        }
        throw error;
      }

      const requestPolicy = classifyRequest(req.method, url.pathname);
      const rateDecision = rateLimiter.consume(
        `credential:${principal.keyId ?? principal.subject}:client:${clientAddress}`,
        requestPolicy
      );
      applyRateDecision(res, rateLimiter, rateDecision);
      if (!rateDecision.allowed) throw new RateLimitError('The credential request rate limit has been exceeded.', rateDecision);
      if (principal.rotationRequired) {
        setDeferredHeader(res, 'x-api-key-rotation-required', 'true');
        if (principal.credentialExpiresAt) setDeferredHeader(res, 'x-api-key-expires-at', principal.credentialExpiresAt);
      }

      const service = registry.forTenant(principal.tenantId);
      const context = { actor: principal.subject };
      const meta = { requestId, tenantId: principal.tenantId, keyId: principal.keyId };

      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/session') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: principal, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/security-status') {
        accessController.authorise(principal, 'security:read');
        return sendJson(res, 200, {
          success: true,
          data: {
            credentials: accessController.credentialHealth(),
            rateLimiting: rateLimiter.health(),
            telemetry: securityTelemetry.summary()
          },
          meta
        }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/security-events') {
        accessController.authorise(principal, 'security:read');
        const limit = parsePositiveInteger(url.searchParams.get('limit'), 100, 500);
        const data = {
          events: securityTelemetry.list({
            limit,
            type: url.searchParams.get('type'),
            severity: url.searchParams.get('severity')
          }),
          integrity: securityTelemetry.verify(),
          archive: {
            health: securityTelemetry.summary().archive,
            integrity: securityTelemetry.verifyArchive()
          }
        };
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/security-archive-events') {
        accessController.authorise(principal, 'security:read');
        const limit = parsePositiveInteger(url.searchParams.get('limit'), 100, 500);
        const afterSequence = parseNonNegativeInteger(url.searchParams.get('afterSequence'), 0);
        const data = securityTelemetry.listArchived({
          limit,
          afterSequence,
          type: url.searchParams.get('type'),
          severity: url.searchParams.get('severity')
        });
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/security-archive-integrity') {
        accessController.authorise(principal, 'security:read');
        return sendJson(res, 200, { success: true, data: securityTelemetry.verifyArchive(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/overview') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: service.getOverview(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/universe') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: service.getUniverse(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/engagements') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: service.getEngagements(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/findings') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: service.getFindings(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/providers') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: service.getProviders(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/governance-events') {
        accessController.authorise(principal, 'governance:read');
        const limit = parsePositiveInteger(url.searchParams.get('limit'), 100, 500);
        return sendJson(res, 200, { success: true, data: registry.listGovernanceEvents(principal.tenantId, { limit }), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/governance-integrity') {
        accessController.authorise(principal, 'governance:read');
        return sendJson(res, 200, { success: true, data: registry.verifyGovernanceIntegrity(principal.tenantId), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/persistence-health') {
        accessController.authorise(principal, 'governance:read');
        return sendJson(res, 200, { success: true, data: registry.getPersistenceHealth(), meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/coordination-status') {
        accessController.authorise(principal, 'coordination:read');
        const data = typeof registry.getCoordinationStatus === 'function'
          ? registry.getCoordinationStatus(principal.tenantId)
          : { status: 'disabled', enabled: false, mode: 'disabled' };
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/resilience-status') {
        accessController.authorise(principal, 'resilience:read');
        const data = {
          ...registry.getResilienceStatus(principal.tenantId, {
            drillMaxAgeDays: scheduler.status().drillMaxAgeDays
          }),
          scheduler: scheduler.status()
        };
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/backups') {
        accessController.authorise(principal, 'backup:read');
        return sendJson(res, 200, { success: true, data: registry.listTenantBackups(principal.tenantId), meta }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/backups') {
        accessController.authorise(principal, 'backup:write');
        const input = await readJson(req);
        const data = registry.createTenantBackup(principal.tenantId, {
          actor: principal.subject,
          reason: input.reason,
          kind: 'manual'
        });
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/replicas') {
        accessController.authorise(principal, 'replica:read');
        return sendJson(res, 200, { success: true, data: registry.listTenantReplicas(principal.tenantId), meta }, requestId);
      }
      const backupVerifyMatch = url.pathname.match(/^\/api\/workforce-audit\/backups\/([^/]+)\/verify$/);
      if (req.method === 'POST' && backupVerifyMatch) {
        accessController.authorise(principal, 'backup:read');
        const data = registry.verifyTenantBackup(principal.tenantId, decodeURIComponent(backupVerifyMatch[1]));
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      const backupReplicateMatch = url.pathname.match(/^\/api\/workforce-audit\/backups\/([^/]+)\/replicate$/);
      if (req.method === 'POST' && backupReplicateMatch) {
        accessController.authorise(principal, 'replica:write');
        const input = await readJson(req);
        const data = registry.replicateTenantBackup(
          principal.tenantId,
          decodeURIComponent(backupReplicateMatch[1]),
          { actor: principal.subject, reason: input.reason }
        );
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      const replicaVerifyMatch = url.pathname.match(/^\/api\/workforce-audit\/replicas\/([^/]+)\/verify$/);
      if (req.method === 'POST' && replicaVerifyMatch) {
        accessController.authorise(principal, 'replica:read');
        const data = registry.verifyTenantReplica(principal.tenantId, decodeURIComponent(replicaVerifyMatch[1]));
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      const backupRestoreMatch = url.pathname.match(/^\/api\/workforce-audit\/backups\/([^/]+)\/restore$/);
      if (req.method === 'POST' && backupRestoreMatch) {
        accessController.authorise(principal, 'backup:restore');
        const input = await readJson(req);
        const data = registry.restoreTenantBackup(
          principal.tenantId,
          decodeURIComponent(backupRestoreMatch[1]),
          {
            actor: principal.subject,
            reason: input.reason,
            expectedHeadHash: input.expectedHeadHash,
            confirmation: input.confirmation,
            dryRun: input.dryRun !== false
          }
        );
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/recovery-drills') {
        accessController.authorise(principal, 'drill:run');
        const input = await readJson(req);
        const data = registry.runRecoveryDrill(principal.tenantId, {
          actor: principal.subject,
          backupId: input.backupId ?? null
        });
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/resilience-cycle') {
        accessController.authorise(principal, 'resilience:run');
        const input = await readJson(req);
        const schedulerStatus = scheduler.status();
        const data = registry.runResilienceCycle([principal.tenantId], {
          actor: principal.subject,
          scheduledBackupIntervalMinutes: input.scheduledBackupIntervalMinutes
            ?? (schedulerStatus.intervalMinutes > 0 ? schedulerStatus.intervalMinutes : 1440),
          drillMaxAgeDays: input.drillMaxAgeDays ?? schedulerStatus.drillMaxAgeDays
        });
        return sendJson(res, 200, { success: true, data, meta }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/engagements') {
        accessController.authorise(principal, 'engagement:write');
        const data = service.createEngagement(await readJson(req), context);
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      const placeholderMatch = url.pathname.match(/^\/api\/workforce-audit\/engagements\/([^/]+)\/placeholders$/);
      if (req.method === 'POST' && placeholderMatch) {
        accessController.authorise(principal, 'fieldwork:write');
        const data = service.addFieldworkPlaceholder(decodeURIComponent(placeholderMatch[1]), await readJson(req), context);
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/findings') {
        accessController.authorise(principal, 'finding:write');
        const data = service.createFinding(await readJson(req), context);
        return sendJson(res, 201, { success: true, data, meta }, requestId);
      }
      return sendJson(res, 404, { success: false, error: 'Route not found.', code: 'NOT_FOUND', meta }, requestId);
    } catch (error) {
      if (error instanceof RateLimitError) {
        safeRecordSecurityEvent(securityTelemetry, {
          type: 'request.rate_limited',
          severity: error.details?.policy === 'sensitive' || error.details?.policy === 'authFailure' ? 'high' : 'warning',
          outcome: 'throttled',
          requestId,
          clientAddress,
          keyId: principal?.keyId,
          subject: principal?.subject,
          tenantId: principal?.tenantId,
          method: req.method,
          route: url.pathname,
          details: { policy: error.details?.policy, retryAfterSeconds: error.details?.retryAfterSeconds }
        });
        return sendJson(res, 429, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, {
          'retry-after': String(error.details?.retryAfterSeconds ?? 1)
        });
      }
      if (error instanceof RateLimitStoreError) {
        safeRecordSecurityEvent(securityTelemetry, {
          type: 'security_control.unavailable', severity: 'critical', outcome: 'failed',
          requestId, clientAddress, keyId: principal?.keyId, subject: principal?.subject,
          tenantId: principal?.tenantId, method: req.method, route: url.pathname,
          details: { control: 'rate_limit_store', reason: error.details?.cause }
        });
        return sendJson(res, 503, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof AuthenticationError) {
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': 'ApiKey realm="workforce-audit"'
        });
      }
      if (error instanceof AuthorizationError) {
        safeRecordSecurityEvent(securityTelemetry, {
          type: error.details?.reason === 'tenant_override' ? 'tenant.override_attempted' : 'authorization.denied',
          severity: error.details?.reason === 'tenant_override' ? 'high' : 'warning',
          outcome: 'denied',
          requestId,
          clientAddress,
          keyId: principal?.keyId ?? error.details?.keyId,
          subject: principal?.subject,
          tenantId: principal?.tenantId,
          method: req.method,
          route: url.pathname,
          details: { reason: error.details?.reason, permission: error.details?.permission }
        });
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId);
      }
      if (error instanceof ValidationError) {
        return sendJson(res, 400, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof BackupNotFoundError || error instanceof ReplicaNotFoundError || error instanceof NotFoundError) {
        return sendJson(res, 404, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof CoordinationBusyError) {
        const retryAfterSeconds = Math.max(1, Math.ceil((error.details?.retryAfterMs ?? 1000) / 1000));
        return sendJson(res, 423, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId, {
          'retry-after': String(retryAfterSeconds)
        });
      }
      if (error instanceof BackupIntegrityError || error instanceof ReplicaIntegrityError || error instanceof RecoveryConflictError
          || error instanceof SecurityArchiveIntegrityError) {
        return sendJson(res, 409, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof CoordinationLostError || error instanceof CoordinationUnavailableError || error instanceof SecurityArchiveError) {
        return sendJson(res, 503, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof BackupError || error instanceof ReplicaError) {
        return sendJson(res, 503, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof PersistenceError || error?.code === 'PERSISTENCE_UNAVAILABLE' || error?.code === 'PERSISTENCE_FENCE_REJECTED') {
        return sendJson(res, 503, {
          success: false,
          error: 'The audit change could not be committed to durable storage.',
          code: error.code ?? 'PERSISTENCE_UNAVAILABLE',
          details: error.details,
          meta: { requestId }
        }, requestId);
      }
      if (error?.code === 'INVALID_JSON') {
        return sendJson(res, 400, { success: false, error: error.message, code: 'INVALID_JSON', meta: { requestId } }, requestId);
      }
      console.error('Unhandled workforce-audit error', { requestId, error });
      return sendJson(res, 500, { success: false, error: 'Internal server error.', code: 'INTERNAL_ERROR', meta: { requestId } }, requestId);
    }
  });

  server.once('listening', () => scheduler.start());
  server.once('close', () => scheduler.stop());
  server.resilienceScheduler = scheduler;
  server.apiSecurity = { rateLimiter, securityTelemetry, securityArchive };
  return server;
}

async function readJson(req) {
  const contentType = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (contentType && contentType !== 'application/json') {
    const error = new Error('Content-Type must be application/json.');
    error.code = 'INVALID_JSON';
    throw error;
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) {
      const error = new Error('Request body exceeds the 1 MB limit.');
      error.code = 'INVALID_JSON';
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    const error = new Error('Request body must be valid JSON.');
    error.code = 'INVALID_JSON';
    throw error;
  }
}

function parsePositiveInteger(value, fallback, maximum) {
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new ValidationError('limit must be a positive integer.', { field: 'limit' });
  return Math.min(parsed, maximum);
}

function parseNonNegativeInteger(value, fallback) {
  if (value === null) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new ValidationError('afterSequence must be a non-negative integer.', { field: 'afterSequence' });
  return parsed;
}

function applyRateDecision(res, rateLimiter, decision) {
  const headers = typeof rateLimiter.headers === 'function' ? rateLimiter.headers(decision) : {};
  for (const [name, value] of Object.entries(headers)) setDeferredHeader(res, name, value);
}

function setDeferredHeader(res, name, value) {
  res.deferredHeaders ??= {};
  res.deferredHeaders[name] = value;
}

function safeRecordSecurityEvent(telemetry, input) {
  try { telemetry.record(input); } catch (error) { console.error('Security telemetry record failed', error); }
}

function publicSecurityHealth({ credentials, rateLimiting, telemetry }) {
  return {
    credentials,
    rateLimiting: omitOperationalPaths(rateLimiting),
    telemetry: {
      ...telemetry,
      archive: omitOperationalPaths(telemetry.archive)
    }
  };
}

function omitOperationalPaths(value) {
  if (!value || typeof value !== 'object') return value;
  const clone = structuredClone(value);
  delete clone.directory;
  delete clone.keyId;
  if (clone.mutex && typeof clone.mutex === 'object') delete clone.mutex.directory;
  return clone;
}

function sendJson(res, status, payload, requestId, additionalHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...(res.deferredHeaders ?? {}),
    ...additionalHeaders
  });
  res.end(JSON.stringify(payload));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => console.log(`BasitClaw listening on http://localhost:${port}`));
}
