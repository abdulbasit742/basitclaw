import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createWorkforceAuditService, NotFoundError, ValidationError } from './services/workforceAuditService.js';

const dashboardPath = fileURLToPath(new URL('../public/workforce-audit.html', import.meta.url));

export function createApp({ service = createWorkforceAuditService() } = {}) {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    try {
      if (req.method === 'GET' && url.pathname === '/health') {
        return sendJson(res, 200, { success: true, data: { status: 'ok' } });
      }
      if (req.method === 'GET' && url.pathname === '/dashboard/workforce-audit') {
        const html = await readFile(dashboardPath, 'utf8');
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        return res.end(html);
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/overview') {
        return sendJson(res, 200, { success: true, data: service.getOverview() });
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/universe') {
        return sendJson(res, 200, { success: true, data: service.getUniverse() });
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/engagements') {
        return sendJson(res, 200, { success: true, data: service.getEngagements() });
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/findings') {
        return sendJson(res, 200, { success: true, data: service.getFindings() });
      }
      if (req.method === 'GET' && url.pathname === '/api/workforce-audit/providers') {
        return sendJson(res, 200, { success: true, data: service.getProviders() });
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/engagements') {
        const data = service.createEngagement(await readJson(req));
        return sendJson(res, 201, { success: true, data });
      }
      const placeholderMatch = url.pathname.match(/^\/api\/workforce-audit\/engagements\/([^/]+)\/placeholders$/);
      if (req.method === 'POST' && placeholderMatch) {
        const data = service.addFieldworkPlaceholder(decodeURIComponent(placeholderMatch[1]), await readJson(req));
        return sendJson(res, 201, { success: true, data });
      }
      if (req.method === 'POST' && url.pathname === '/api/workforce-audit/findings') {
        const data = service.createFinding(await readJson(req));
        return sendJson(res, 201, { success: true, data });
      }
      return sendJson(res, 404, { success: false, error: 'Route not found.', code: 'NOT_FOUND' });
    } catch (error) {
      if (error instanceof ValidationError) {
        return sendJson(res, 400, { success: false, error: error.message, code: error.code, details: error.details });
      }
      if (error instanceof NotFoundError) {
        return sendJson(res, 404, { success: false, error: error.message, code: error.code });
      }
      if (error?.code === 'INVALID_JSON') {
        return sendJson(res, 400, { success: false, error: 'Request body must be valid JSON.', code: 'INVALID_JSON' });
      }
      console.error('Unhandled workforce-audit error', error);
      return sendJson(res, 500, { success: false, error: 'Internal server error.', code: 'INTERNAL_ERROR' });
    }
  });
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) {
      const error = new Error('Payload too large.');
      error.code = 'INVALID_JSON';
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    const error = new Error('Invalid JSON.');
    error.code = 'INVALID_JSON';
    throw error;
  }
}

function sendJson(res, status, payload) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify(payload));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => console.log(`BasitClaw listening on http://localhost:${port}`));
}
