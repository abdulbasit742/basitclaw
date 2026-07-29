import { fileURLToPath } from 'node:url';
import { createSecurityKeyLifecycleFromEnvironment } from '../src/security/securityKeyLifecycle.js';

export function runSecurityKeyCommand(args = process.argv.slice(2), env = process.env) {
  const [command = 'status', keyId] = args;
  const lifecycle = createSecurityKeyLifecycleFromEnvironment(env);
  if (command === 'status') return lifecycle.status();
  if (command === 'archive-can-retire') {
    if (!keyId) throw new TypeError('An archive key ID is required.');
    return lifecycle.archiveCanRetire(keyId);
  }
  if (command === 'alert-can-retire') {
    if (!keyId) throw new TypeError('An alert signing key ID is required.');
    return lifecycle.alertCanRetire(keyId);
  }
  throw new TypeError('Command must be status, archive-can-retire, or alert-can-retire.');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(runSecurityKeyCommand(), null, 2));
  } catch (error) {
    console.error(JSON.stringify({
      success: false,
      code: error.code ?? 'SECURITY_KEY_COMMAND_FAILED',
      error: error.message
    }));
    process.exitCode = 1;
  }
}
