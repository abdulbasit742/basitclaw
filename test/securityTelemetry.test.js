import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';

test('security telemetry fingerprints addresses and maintains a bounded hash chain', () => {
  const telemetry = createSecurityTelemetry({
    pepper: 'telemetry-pepper-123456789',
    maxEvents: 100,
    now: () => new Date('2026-07-29T00:00:00Z')
  });
  telemetry.record({
    type: 'authentication.failed',
    severity: 'warning',
    outcome: 'denied',
    clientAddress: '203.0.113.10',
    requestId: 'req-1',
    details: { reason: 'invalid_key', apiKey: 'must-not-leak' }
  });
  telemetry.record({
    type: 'request.rate_limited',
    severity: 'high',
    outcome: 'throttled',
    clientAddress: '203.0.113.10',
    requestId: 'req-2'
  });
  const events = telemetry.list({ limit: 10 });
  assert.equal(events.length, 2);
  assert.equal(events[0].ipFingerprint, events[1].ipFingerprint);
  assert.doesNotMatch(JSON.stringify(events), /203\.0\.113\.10|must-not-leak/);
  assert.equal(telemetry.verify().valid, true);
  assert.equal(telemetry.summary().countsByType['authentication.failed'], 1);
});
