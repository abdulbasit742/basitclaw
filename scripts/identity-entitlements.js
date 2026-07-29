import { fileURLToPath } from 'node:url';
import { createIdentityEntitlementRegistryFromEnvironment } from '../src/security/identityEntitlementRegistry.js';

export function runIdentityEntitlementCommand(command = 'status', args = [], env = process.env, options = {}) {
  const registry = options.registry ?? createIdentityEntitlementRegistryFromEnvironment(env, options);
  if (command === 'status') return registry.health();
  if (command === 'list') {
    const count = numeric(args[0] ?? 100, 'count', 1, 500);
    return registry.list({ count });
  }
  if (command === 'events') {
    const limit = numeric(args[0] ?? 100, 'limit', 1, 1000);
    return { events: registry.listEvents({ limit }) };
  }
  if (command === 'review-status') return registry.reviewStatus();
  throw new TypeError('Command must be status, list, events, or review-status.');
}

function numeric(value, field, minimum, maximum) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) throw new TypeError(`${field} must be from ${minimum} to ${maximum}.`);
  return number;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [command = 'status', ...args] = process.argv.slice(2);
    console.log(JSON.stringify(runIdentityEntitlementCommand(command, args), null, 2));
  } catch (error) {
    console.error(JSON.stringify({ success: false, code: error.code ?? 'IDENTITY_ENTITLEMENT_COMMAND_FAILED', error: error.message }));
    process.exitCode = 1;
  }
}
