import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createSharedFileRateLimiter, RateLimitStoreError } from '../src/security/sharedRateLimiter.js';
import { createAdaptiveRateLimiterFromEnvironment } from '../src/security/rateLimiter.js';

const policies = {
  burst: { limit: 2, windowMs: 1000 }, authFailure: { limit: 2, windowMs: 1000 },
  read: { limit: 2, windowMs: 1000 }, write: { limit: 1, windowMs: 1000 },
  sensitive: { limit: 1, windowMs: 1000 }
};
const resolveClientAddress = () => '127.0.0.1';

function setup(t) {
  const root = mkdtempSync(join(tmpdir(), 'basitclaw-shared-rate-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

test('shared limiter enforces one quota across independent instances', (t) => {
  const root = setup(t);
  const now = () => new Date('2026-07-29T00:00:00.000Z');
  const first = createSharedFileRateLimiter({ directory: root, policies, now, resolveClientAddress });
  const second = createSharedFileRateLimiter({ directory: root, policies, now, resolveClientAddress });
  assert.equal(first.consume('credential-a', 'read').allowed, true);
  assert.equal(second.consume('credential-a', 'read').allowed, true);
  assert.equal(first.consume('credential-a', 'read').allowed, false);
  assert.equal(first.health().distributed, true);
});

test('shared limiter resets at the next fixed window', (t) => {
  const root = setup(t);
  let current = new Date('2026-07-29T00:00:00.000Z');
  const limiter = createSharedFileRateLimiter({ directory: root, policies, now: () => new Date(current), resolveClientAddress });
  limiter.consume('credential-a', 'write');
  assert.equal(limiter.consume('credential-a', 'write').allowed, false);
  current = new Date('2026-07-29T00:00:01.001Z');
  assert.equal(limiter.consume('credential-a', 'write').allowed, true);
});

test('corrupt shared buckets fail closed', (t) => {
  const root = setup(t);
  const limiter = createSharedFileRateLimiter({ directory: root, policies, resolveClientAddress });
  const hash = createHash('sha256').update('read:credential-a').digest('hex');
  mkdirSync(join(root, 'buckets'), { recursive: true });
  writeFileSync(join(root, 'buckets', `${hash}.json`), '{not-json');
  assert.throws(() => limiter.consume('credential-a', 'read'), RateLimitStoreError);
});

test('production multi-process mode requires the shared limiter unless explicitly waived', (t) => {
  const root = setup(t);
  assert.throws(() => createAdaptiveRateLimiterFromEnvironment({
    NODE_ENV: 'production', WORKFORCE_AUDIT_COORDINATION_MODE: 'file-lease',
    WORKFORCE_AUDIT_RATE_LIMIT_MODE: 'memory'
  }), /shared-file rate limiter is required/);
  const limiter = createAdaptiveRateLimiterFromEnvironment({
    NODE_ENV: 'production', WORKFORCE_AUDIT_COORDINATION_MODE: 'file-lease',
    WORKFORCE_AUDIT_RATE_LIMIT_MODE: 'shared-file', WORKFORCE_AUDIT_RATE_LIMIT_DIR: root
  });
  assert.equal(limiter.health().required, true);
  assert.equal(limiter.health().distributed, true);
});
