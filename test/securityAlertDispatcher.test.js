import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createSecurityAlertDispatcher } from '../src/security/securityAlertDispatcher.js';
import { createSecurityAlertOutbox } from '../src/security/securityAlertOutbox.js';

const secret = 'security-alert-signing-secret-1234567890';
const event = Object.freeze({
  id: 'SEC-1',
  hash: 'a'.repeat(64),
  occurredAt: '2026-07-29T00:00:00Z',
  type: 'authentication.failed',
  severity: 'high',
  outcome: 'denied',
  details: { reason: 'invalid_key' }
});

async function directory() {
  return mkdtemp(resolve(tmpdir(), 'basitclaw-alert-'));
}

test('alert policy filters low severity events and deduplicates eligible events', async () => {
  const root = await directory();
  const dispatcher = createSecurityAlertDispatcher({
    endpoint: 'https://alerts.example.test/hook',
    signingSecret: secret,
    outboxDirectory: root,
    fetchImpl: async () => new Response(null, { status: 204 })
  });
  assert.equal(dispatcher.enqueue({ ...event, severity: 'warning' }).filtered, true);
  assert.equal(dispatcher.enqueue(event).enqueued, true);
  assert.equal(dispatcher.enqueue(event).duplicate, true);
  assert.equal(dispatcher.health().outbox.pending, 1);
});

test('alert delivery signs payload and records a durable receipt', async () => {
  const root = await directory();
  let observed;
  const dispatcher = createSecurityAlertDispatcher({
    endpoint: 'https://alerts.example.test/hook',
    signingSecret: secret,
    outboxDirectory: root,
    fetchImpl: async (url, options) => {
      observed = { url, options };
      return new Response(null, { status: 202, headers: { 'x-request-id': 'receiver-1' } });
    }
  });
  dispatcher.enqueue(event);
  const result = await dispatcher.dispatchDue();
  assert.equal(result.delivered, 1);
  assert.match(observed.options.headers['x-basitclaw-signature'], /^sha256=/);
  assert.equal(dispatcher.verifySignature(
    observed.options.body,
    observed.options.headers['x-basitclaw-timestamp'],
    observed.options.headers['x-basitclaw-signature']
  ), true);
  assert.equal(dispatcher.verifySignature(
    `${observed.options.body}tampered`,
    observed.options.headers['x-basitclaw-timestamp'],
    observed.options.headers['x-basitclaw-signature']
  ), false);
  assert.equal(dispatcher.health().outbox.pending, 0);
  assert.equal((await readdir(resolve(root, 'delivered'))).length, 1);
});

test('retryable failures respect Retry-After and then dead-letter', async () => {
  const root = await directory();
  let current = new Date('2026-07-29T00:00:00Z');
  const dispatcher = createSecurityAlertDispatcher({
    endpoint: 'https://alerts.example.test/hook',
    signingSecret: secret,
    outboxDirectory: root,
    maxAttempts: 2,
    now: () => new Date(current),
    fetchImpl: async () => new Response(null, { status: 429, headers: { 'retry-after': '2' } })
  });
  dispatcher.enqueue(event);
  const first = await dispatcher.dispatchDue();
  assert.equal(first.retried, 1);
  const pendingFile = (await readdir(resolve(root, 'pending')))[0];
  const pending = JSON.parse(await readFile(resolve(root, 'pending', pendingFile), 'utf8'));
  assert.equal(pending.nextAttemptAt, '2026-07-29T00:00:02.000Z');
  current = new Date('2026-07-29T00:00:03Z');
  const second = await dispatcher.dispatchDue();
  assert.equal(second.deadLettered, 1);
  assert.equal(dispatcher.listDeadLetters().length, 1);
  assert.equal(dispatcher.health().outbox.status, 'degraded');
});

test('two outbox instances claim a shared delivery only once', async () => {
  const root = await directory();
  const first = createSecurityAlertOutbox({ directory: root });
  const second = createSecurityAlertOutbox({ directory: root });
  first.enqueue(event);
  assert.equal(first.claimDue().length, 1);
  assert.equal(second.claimDue().length, 0);
});

test('expired in-flight claims recover into pending state', async () => {
  const root = await directory();
  let current = new Date('2026-07-29T00:00:00Z');
  const outbox = createSecurityAlertOutbox({
    directory: root,
    now: () => new Date(current),
    inflightLeaseMs: 1000
  });
  outbox.enqueue(event);
  const [claim] = outbox.claimDue();
  assert.ok(claim.claimToken);
  current = new Date('2026-07-29T00:00:02Z');
  assert.equal(outbox.health().pending, 1);
  assert.equal(outbox.health().inflight, 0);
});

test('a committed destination removes an orphaned in-flight claim without resend', async () => {
  const root = await directory();
  const outbox = createSecurityAlertOutbox({ directory: root });
  outbox.enqueue(event);
  const [claim] = outbox.claimDue();
  const filename = `${claim.deliveryId}.json`;
  await writeFile(resolve(root, 'delivered', filename), JSON.stringify({
    version: 1,
    deliveryId: claim.deliveryId,
    state: 'delivered'
  }));
  const health = outbox.health();
  assert.equal(health.pending, 0);
  assert.equal(health.inflight, 0);
  assert.equal((await readdir(resolve(root, 'delivered'))).length, 1);
});

test('dead letters can be explicitly requeued', async () => {
  const root = await directory();
  const dispatcher = createSecurityAlertDispatcher({
    endpoint: 'https://alerts.example.test/hook',
    signingSecret: secret,
    outboxDirectory: root,
    maxAttempts: 1,
    fetchImpl: async () => new Response(null, { status: 400 })
  });
  const enqueued = dispatcher.enqueue(event);
  await dispatcher.dispatchDue();
  dispatcher.requeue(enqueued.deliveryId);
  assert.equal(dispatcher.health().outbox.pending, 1);
  assert.equal(dispatcher.listDeadLetters().length, 0);
});
