import test from 'node:test';
import assert from 'node:assert/strict';
import { createSecurityTelemetry } from '../src/security/securityTelemetry.js';
import { createSecurityAlertDispatcherFromEnvironment } from '../src/security/securityAlertDispatcher.js';

function disabledArchive() {
  return {
    enabled: false,
    append() {},
    health: () => ({ status: 'disabled', enabled: false, required: false, mode: 'disabled' })
  };
}

test('telemetry sends only its sanitised event into alert delivery', () => {
  const received = [];
  const alertDispatcher = {
    enabled: true,
    enqueue(event) { received.push(event); },
    health: () => ({ status: 'ready', enabled: true, required: true, mode: 'test-delivery' })
  };
  const telemetry = createSecurityTelemetry({
    pepper: 'telemetry-pepper-123456789',
    archive: disabledArchive(),
    alertDispatcher,
    now: () => new Date('2026-07-29T00:00:00Z')
  });
  telemetry.record({
    type: 'authentication.failed',
    severity: 'high',
    outcome: 'denied',
    clientAddress: '203.0.113.10',
    details: { reason: 'invalid_key', apiKey: 'must-not-leak', password: 'must-not-leak' }
  });
  assert.equal(received.length, 1);
  assert.doesNotMatch(JSON.stringify(received), /203\.0\.113\.10|must-not-leak/);
  assert.match(received[0].ipFingerprint, /^[a-f0-9]{24}$/);
  const summary = telemetry.summary();
  assert.equal(summary.alertDelivery.status, 'ready');
  assert.equal(summary.archive.required, true);
  assert.equal(summary.archive.status, 'ready');
});

test('required alert delivery failure marks the security evidence pipeline unavailable', () => {
  const alertDispatcher = {
    enabled: true,
    enqueue() { throw new Error('disk unavailable'); },
    health: () => ({ status: 'unavailable', enabled: true, required: true, mode: 'test-delivery' })
  };
  const telemetry = createSecurityTelemetry({
    pepper: 'telemetry-pepper-123456789',
    archive: disabledArchive(),
    alertDispatcher
  });
  telemetry.record({ type: 'request.rate_limited', severity: 'high', outcome: 'throttled' });
  const summary = telemetry.summary();
  assert.equal(summary.status, 'unavailable');
  assert.equal(summary.archive.required, true);
  assert.equal(summary.archive.status, 'unavailable');
  assert.equal(summary.alertDelivery.enqueueFailures, 1);
});

test('required alert delivery cannot be configured as disabled', () => {
  assert.throws(() => createSecurityAlertDispatcherFromEnvironment({
    WORKFORCE_AUDIT_SECURITY_ALERT_MODE: 'disabled',
    WORKFORCE_AUDIT_SECURITY_ALERT_REQUIRED: 'true'
  }), /cannot be disabled/);
});
