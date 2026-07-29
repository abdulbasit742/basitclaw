import {
  createDisabledSecurityAlertDispatcher,
  createSecurityAlertDispatcherFromEnvironment
} from './securityAlertDispatcher.js';
import { createSecurityAlertOutbox } from './securityAlertOutbox.js';

export function createSecurityAlertRuntimeFromEnvironment(env = process.env, options = {}) {
  const mode = String(env.WORKFORCE_AUDIT_SECURITY_ALERT_MODE ?? 'disabled');
  const outbox = options.outbox ?? (mode === 'webhook' ? createSecurityAlertOutbox({
    directory: env.WORKFORCE_AUDIT_SECURITY_ALERT_OUTBOX_DIR
      ?? '.runtime-data/workforce-audit-security-alerts',
    inflightLeaseMs: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_INFLIGHT_LEASE_MS ?? 60_000),
    deliveredRetention: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_DELIVERED_RETENTION ?? 10_000),
    deadLetterRetention: Number(env.WORKFORCE_AUDIT_SECURITY_ALERT_DEAD_LETTER_RETENTION ?? 2_000),
    lockLeaseMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_LOCK_MS ?? 10_000),
    lockAcquireTimeoutMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_ACQUIRE_TIMEOUT_MS ?? 2_000),
    lockRetryMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_RETRY_MS ?? 10),
    now: options.now
  }) : null);
  const dispatcher = createSecurityAlertDispatcherFromEnvironment(env, { ...options, outbox });
  const autoStart = String(env.WORKFORCE_AUDIT_SECURITY_ALERT_AUTO_START ?? 'true') === 'true';
  if (dispatcher.enabled && autoStart) dispatcher.start();
  return dispatcher;
}

export function createDisabledSecurityAlertRuntime(options = {}) {
  return createDisabledSecurityAlertDispatcher(options);
}
