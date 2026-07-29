import {
  PrivilegedAccessError,
  PrivilegedAccessStoreError
} from './privilegedAccessRegistry.js';

const VALIDATED_METHODS = new Set([
  'requestAccess', 'approve', 'deny', 'cancel', 'revoke',
  'activateBreakGlass', 'completePostReview'
]);

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
            return value.apply(target, args);
          } catch (error) {
            if (error instanceof TypeError) {
              throw new PrivilegedAccessError(
                error.message,
                'PRIVILEGED_ACCESS_INPUT_INVALID',
                {},
                400
              );
            }
            throw error;
          }
        };
      }

      return value.bind(target);
    }
  });
}
