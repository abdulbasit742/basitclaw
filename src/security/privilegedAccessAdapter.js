import { permissionsForRole } from './accessControl.js';
import {
  PrivilegedAccessError,
  PrivilegedAccessStoreError
} from './privilegedAccessRegistry.js';

const PRINCIPAL_ARGUMENT = Object.freeze({
  requestAccess: 0,
  approve: 1,
  deny: 1,
  cancel: 1,
  revoke: 1,
  activateBreakGlass: 0,
  completePostReview: 1
});
const VALIDATED_METHODS = new Set(Object.keys(PRINCIPAL_ARGUMENT));

/**
 * Normalises the public privileged-access contract without caching state.
 * Every call still reaches the underlying mutex-protected registry so
 * revocation and expiry remain immediately visible across processes.
 */
export function createPrivilegedAccessAdapter(registry) {
  if (!registry || typeof registry.authorise !== 'function') {
    throw new TypeError('A privileged-access registry is required.');
  }
  if (registry.__privilegedAccessAdapter === true) return registry;

  return new Proxy(registry, {
    get(target, property, receiver) {
      if (property === '__privilegedAccessAdapter') return true;
      const value = Reflect.get(target, property, receiver);
      if (typeof value !== 'function') return value;

      if (property === 'authorise') {
        return (principal, permission) => {
          try {
            return value.call(target, principal, permission);
          } catch (error) {
            if (target.mode === 'observe' && error instanceof PrivilegedAccessStoreError) {
              return Object.freeze({
                ...principal,
                privilegedAccess: Object.freeze({
                  status: 'observed',
                  permission,
                  reason: error.code,
                  enforced: false
                })
              });
            }
            throw error;
          }
        };
      }

      if (VALIDATED_METHODS.has(property)) {
        return (...args) => {
          try {
            validatePrincipal(args[PRINCIPAL_ARGUMENT[property]]);
            return value.apply(target, args);
          } catch (error) {
            if (error instanceof TypeError) throw inputError(error.message);
            if (error instanceof PrivilegedAccessStoreError && looksLikeValidationFailure(error.details?.cause)) {
              throw inputError(String(error.details.cause));
            }
            throw error;
          }
        };
      }

      return value.bind(target);
    }
  });
}

function validatePrincipal(principal) {
  const subject = String(principal?.subject ?? '').trim();
  const tenantId = String(principal?.tenantId ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{1,255}$/.test(subject)) {
    throw new TypeError('subject must be a safe identifier.');
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(tenantId)) {
    throw new TypeError('tenantId must be a safe identifier.');
  }
  permissionsForRole(String(principal?.role ?? ''));
}

function looksLikeValidationFailure(cause) {
  const value = String(cause ?? '');
  return /must (?:be|contain)|Unsupported workforce-audit role|required\.|safe identifier|unsupported credential status/i.test(value);
}

function inputError(message) {
  return new PrivilegedAccessError(
    message,
    'PRIVILEGED_ACCESS_INPUT_INVALID',
    {},
    400
  );
}
