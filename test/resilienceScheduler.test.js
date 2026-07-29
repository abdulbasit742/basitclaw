import test from 'node:test';
import assert from 'node:assert/strict';
import { createResilienceScheduler } from '../src/resilience/resilienceScheduler.js';

test('scheduler is disabled when interval is zero', () => {
  let calls = 0;
  const scheduler = createResilienceScheduler({
    registry: { runResilienceCycle: () => { calls += 1; } },
    tenantIds: ['tenant-a'],
    intervalMinutes: 0
  });
  assert.equal(scheduler.runOnce().status, 'disabled');
  assert.equal(calls, 0);
});

test('scheduler deduplicates tenants and forwards resilience policy', () => {
  const calls = [];
  const scheduler = createResilienceScheduler({
    registry: { runResilienceCycle: (tenants, options) => { calls.push({ tenants, options }); return { status: 'completed' }; } },
    tenantIds: ['tenant-a', 'tenant-a', 'tenant-b'],
    intervalMinutes: 1440,
    drillMaxAgeDays: 30,
    tickSeconds: 60
  });
  assert.equal(scheduler.runOnce().status, 'completed');
  assert.deepEqual(calls[0].tenants, ['tenant-a', 'tenant-b']);
  assert.equal(calls[0].options.drillMaxAgeDays, 30);
});
