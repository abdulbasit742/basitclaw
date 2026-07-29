import { createEncryptedSnapshotStoreFromEnvironment } from '../persistence/encryptedSnapshotStore.js';
import { createGovernanceLedger } from './governanceLedger.js';
import { createWorkforceAuditService } from './workforceAuditService.js';

export function createWorkforceAuditRegistry({
  now = () => new Date(),
  ledger = createGovernanceLedger({ now }),
  store = createEncryptedSnapshotStoreFromEnvironment()
} = {}) {
  const services = new Map();

  function forTenant(tenantId) {
    validateTenantId(tenantId);
    if (!services.has(tenantId)) {
      const snapshot = store.load(tenantId);
      ledger.importTenant(tenantId, snapshot?.governanceEvents ?? []);
      const persist = (state) => {
        store.save(tenantId, {
          schemaVersion: 1,
          tenantId,
          savedAt: now().toISOString(),
          state,
          governanceEvents: ledger.exportTenant(tenantId)
        });
      };
      const service = createWorkforceAuditService({
        now,
        tenantId,
        ledger,
        initialState: snapshot?.state ?? null,
        persist
      });
      services.set(tenantId, service);
    }
    return services.get(tenantId);
  }

  return {
    forTenant,
    listGovernanceEvents: (tenantId, options) => ledger.list(tenantId, options),
    verifyGovernanceIntegrity: (tenantId) => ledger.verify(tenantId),
    getPersistenceHealth: () => store.health(),
    tenantCount: () => services.size
  };
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) {
    throw new TypeError('tenantId must be a safe identifier.');
  }
}
