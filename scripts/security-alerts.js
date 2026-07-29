import { fileURLToPath } from 'node:url';
import { createSecurityAlertDispatcherFromEnvironment } from '../src/security/securityAlertDispatcher.js';

export async function runSecurityAlertCommand(args = process.argv.slice(2), env = process.env) {
  const [command = 'status', value] = args;
  const dispatcher = createSecurityAlertDispatcherFromEnvironment(env);
  try {
    if (command === 'status') return dispatcher.health();
    if (command === 'dispatch') {
      const limit = value === undefined ? undefined : positiveInteger(value, 'limit', 500);
      return dispatcher.dispatchDue(limit ? { limit } : {});
    }
    if (command === 'dead-letters') {
      const limit = value === undefined ? 100 : positiveInteger(value, 'limit', 500);
      return { deadLetters: dispatcher.listDeadLetters({ limit }) };
    }
    if (command === 'requeue') {
      if (!value) throw new TypeError('A delivery ID is required for requeue.');
      return dispatcher.requeue(value);
    }
    throw new TypeError('Command must be status, dispatch, dead-letters, or requeue.');
  } finally {
    dispatcher.stop?.();
  }
}

function positiveInteger(value, field, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new TypeError(`${field} must be an integer from 1 to ${maximum}.`);
  }
  return parsed;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runSecurityAlertCommand()
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error) => {
      console.error(JSON.stringify({ success: false, code: error.code ?? 'SECURITY_ALERT_COMMAND_FAILED', error: error.message }));
      process.exitCode = 1;
    });
}
