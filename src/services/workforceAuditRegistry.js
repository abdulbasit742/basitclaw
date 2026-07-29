import { createGovernanceLedger } from './governanceLedger.js';
import { createWorkforceAuditService } from './workforceAuditService.js';

export function createWorkforceAuditRegistry({ now = () => new Date(), ledger = createGovernanceLedger({ now }) } = {}) {
  const services = new Map();

  function forTenant(tenantId) {
    validateTenantId(tenantId);
    if (!services.has(tenantId)) {
      services.set(tenantId, createWorkforceAuditService({ now, tenantId, ledger }));
    }
    return services.get(tenantId);
  }

  return {
    forTenant,
    listGovernanceEvents: (tenantId, options) => ledger.list(tenantId, options),
    verifyGovernanceIntegrity: (tenantId) => ledger.verify(tenantId),
    tenantCount: () => services.size
  };
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) {
    throw new TypeError('tenantId must be a safe identifier.');
  }
}
