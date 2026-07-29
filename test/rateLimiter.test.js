import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyRequest,
  createAdaptiveRateLimiter,
  createAdaptiveRateLimiterFromEnvironment,
  resolveClientAddress
} from '../src/security/rateLimiter.js';

const policies = {
  burst: { limit: 2, windowMs: 1000 },
  authFailure: { limit: 2, windowMs: 1000 },
  read: { limit: 2, windowMs: 1000 },
  write: { limit: 1, windowMs: 1000 },
  sensitive: { limit: 1, windowMs: 1000 }
};

test('rate limits enforce policy and reset at the next window', () => {
  let current = new Date('2026-07-29T00:00:00.000Z');
  const limiter = createAdaptiveRateLimiter({ now: () => new Date(current), policies });
  assert.equal(limiter.consume('subject-a', 'read').allowed, true);
  assert.equal(limiter.consume('subject-a', 'read').allowed, true);
  const denied = limiter.consume('subject-a', 'read');
  assert.equal(denied.allowed, false);
  assert.equal(denied.remaining, 0);
  current = new Date('2026-07-29T00:00:01.100Z');
  assert.equal(limiter.consume('subject-a', 'read').allowed, true);
});

test('request classification separates sensitive, write, and read traffic', () => {
  assert.equal(classifyRequest('POST', '/api/workforce-audit/backups/B-1/restore'), 'sensitive');
  assert.equal(classifyRequest('POST', '/api/workforce-audit/findings'), 'write');
  assert.equal(classifyRequest('GET', '/api/workforce-audit/overview'), 'read');
});

test('client address trusts only the configured proxy depth', () => {
  const request = { headers: { 'x-forwarded-for': '203.0.113.10, 10.0.0.4' }, socket: { remoteAddress: '10.0.0.5' } };
  assert.equal(resolveClientAddress(request, 0), '10.0.0.5');
  assert.equal(resolveClientAddress(request, 1), '10.0.0.4');
  assert.equal(resolveClientAddress(request, 2), '203.0.113.10');
});

test('unknown limiter modes fail closed', () => {
  assert.throws(() => createAdaptiveRateLimiterFromEnvironment({
    WORKFORCE_AUDIT_RATE_LIMIT_MODE: 'typo'
  }), /must be memory, shared-file, or disabled/);
});
