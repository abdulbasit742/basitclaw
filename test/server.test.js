import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';

test('health and overview endpoints return the standard envelope', async (t) => {
  const server = createApp();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;

  const health = await fetch(`${base}/health`).then((response) => response.json());
  assert.deepEqual(health, { success: true, data: { status: 'ok' } });

  const overviewResponse = await fetch(`${base}/api/workforce-audit/overview`);
  const overview = await overviewResponse.json();
  assert.equal(overviewResponse.status, 200);
  assert.equal(overview.success, true);
  assert.equal(overview.data.universe.total, 3);
});

test('dashboard route serves the workforce audit page', async (t) => {
  const server = createApp();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const address = server.address();
  const response = await fetch(`http://127.0.0.1:${address.port}/dashboard/workforce-audit`);
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /Workforce Audit Assurance/);
});
