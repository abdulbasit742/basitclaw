import {
  createDisabledSecurityAlertDispatcher,
  createSecurityAlertDispatcherFromEnvironment
} from './securityAlertDispatcher.js';

export function createSecurityAlertRuntimeFromEnvironment(env = process.env, options = {}) {
  const dispatcher = createSecurityAlertDispatcherFromEnvironment(env, options);
  const autoStart = String(env.WORKFORCE_AUDIT_SECURITY_ALERT_AUTO_START ?? 'true') === 'true';
  if (dispatcher.enabled && autoStart) dispatcher.start();
  return dispatcher;
}

export function createDisabledSecurityAlertRuntime(options = {}) {
  return createDisabledSecurityAlertDispatcher(options);
}
