import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  BackupError,
  BackupIntegrityError,
  BackupNotFoundError,
  RecoveryConflictError
} from './services/workforceAuditRegistry.js';
import { PersistenceError } from './persistence/encryptedSnapshotStore.js';
import { AuthenticationError, AuthorizationError, createAccessController } from './security/accessControl.js';
import { createWorkforceAuditRegistry } from './services/workforceAuditRegistry.js';
import { NotFoundError, ValidationError } from './services/workforceAuditService.js';

const dashboardPath = fileURLToPath(new URL('../public/workforce-audit.html', import.meta.url));

export function createApp({
  registry = createWorkforceAuditRegistry(),
  accessController = createAccessController()
} = {}) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const requestId = randomUUID();
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        const persistence = registry.getPersistenceHealth();
        const status = persistence.status === 'ready' && persistence.backups?.status === 'ready' ? 200 : 503;
        return sendJson(res, status, {
          success: status === 200,
          data: { status: status === 200 ? 'ok' : 'degraded', persistence },
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

      const principal = accessController.authenticate(req);
      const service = registry.forTenant(principal.tenantId);
      const context = { actor: principal.subject };
      const meta = { requestId, tenantId: principal.tenantId };

      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/session') {
        accessController.authorise(principal, 'audit:read');
        return sendJson(res, 200, { success: true, data: principal, meta }, requestId);
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
      const backupVerifyMatch = url.pathname.match(/^\/api\/workforce-audit\/backups\/([^/]+)\/verify$/);
      if (req.method === 'POST' && backupVerifyMatch) {
        accessController.authorise(principal, 'backup:read');
        const data = registry.verifyTenantBackup(principal.tenantId, decodeURIComponent(backupVerifyMatch[1]));
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
      if (error instanceof AuthenticationError) {
        return sendJson(res, 401, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId, {
          'www-authenticate': 'ApiKey realm="workforce-audit"'
        });
      }
      if (error instanceof AuthorizationError) {
        return sendJson(res, 403, { success: false, error: error.message, code: error.code, meta: { requestId } }, requestId);
      }
      if (error instanceof ValidationError) {
        return sendJson(res, 400, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof BackupNotFoundError || error instanceof NotFoundError) {
        return sendJson(res, 404, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof BackupIntegrityError || error instanceof RecoveryConflictError) {
        return sendJson(res, 409, { success: false, error: error.message, code: error.code, details: error.details, meta: { requestId } }, requestId);
      }
      if (error instanceof BackupError) {
        return sendJson(res, 503, { success: false, error: 'The workforce-audit recovery operation is unavailable.', code: error.code, meta: { requestId } }, requestId);
      }
      if (error instanceof PersistenceError || error?.code === 'PERSISTENCE_UNAVAILABLE') {
        return sendJson(res, 503, {
          success: false,
          error: 'The audit change could not be committed to durable storage.',
          code: 'PERSISTENCE_UNAVAILABLE',
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

function sendJson(res, status, payload, requestId, additionalHeaders = {}) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-request-id': requestId,
    ...additionalHeaders
  });
  res.end(JSON.stringify(payload));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => console.log(`BasitClaw listening on http://localhost:${port}`));
}
