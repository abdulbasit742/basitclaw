import { createFileLeaseCoordinatorFromEnvironment } from './fileLeaseCoordinator.js';
import { bindFencingToken, createFencedSnapshotStore } from './fencedSnapshotStore.js';
import { createEncryptedSnapshotStoreFromEnvironment } from '../persistence/encryptedSnapshotStore.js';
import { createWorkforceAuditRegistry } from '../services/workforceAuditRegistry.js';

export function createCoordinatedWorkforceAuditRegistry({
  registryFactory,
  coordinator,
  store
} = {}) {
  if (typeof registryFactory !== 'function') throw new TypeError('A workforce-audit registry factory is required.');
  if (!coordinator || typeof coordinator.withLease !== 'function') throw new TypeError('A write coordinator is required.');
  if (!store || typeof store.readEncrypted !== 'function') throw new TypeError('A fenced snapshot store is required.');

  const seenTenants = new Set();

  function createRegistry(lease = null) {
    const operationStore = lease ? bindFencingToken(store, lease.fencingToken) : createReadOnlyStore(store);
    return registryFactory({ store: operationStore, lease });
  }

  function read(tenantId, operation) {
    validateTenantId(tenantId);
    seenTenants.add(tenantId);
    return operation(createRegistry(), tenantId);
  }

  function write(tenantId, operation) {
    validateTenantId(tenantId);
    seenTenants.add(tenantId);
    return coordinator.withLease(tenantId, (lease) => {
      lease.assertValid();
      const result = operation(createRegistry(lease), tenantId, lease);
      lease.assertValid();
      return result;
    });
  }

  function forTenant(tenantId) {
    validateTenantId(tenantId);
    seenTenants.add(tenantId);
    return Object.freeze({
      getOverview: () => read(tenantId, (registry) => registry.forTenant(tenantId).getOverview()),
      getUniverse: () => read(tenantId, (registry) => registry.forTenant(tenantId).getUniverse()),
      getEngagements: () => read(tenantId, (registry) => registry.forTenant(tenantId).getEngagements()),
      getFindings: () => read(tenantId, (registry) => registry.forTenant(tenantId).getFindings()),
      getProviders: () => read(tenantId, (registry) => registry.forTenant(tenantId).getProviders()),
      exportState: () => read(tenantId, (registry) => registry.forTenant(tenantId).exportState()),
      createEngagement: (input, context) => write(tenantId, (registry) => registry.forTenant(tenantId).createEngagement(input, context)),
      addFieldworkPlaceholder: (engagementId, input, context) => write(
        tenantId,
        (registry) => registry.forTenant(tenantId).addFieldworkPlaceholder(engagementId, input, context)
      ),
      createFinding: (input, context) => write(tenantId, (registry) => registry.forTenant(tenantId).createFinding(input, context))
    });
  }

  function runResilienceCycle(tenantIds, options = {}) {
    const uniqueTenants = [...new Set(tenantIds.map((value) => String(value)))];
    const results = [];
    for (const tenantId of uniqueTenants) {
      try {
        const cycle = write(tenantId, (registry) => registry.runResilienceCycle([tenantId], options));
        const item = cycle.results?.[0] ?? { tenantId, status: cycle.status };
        results.push(item);
      } catch (error) {
        results.push({
          tenantId,
          status: 'failed',
          code: error.code ?? 'WRITE_COORDINATION_FAILED',
          error: error.message
        });
      }
    }
    return {
      status: results.some((item) => item.status === 'failed') ? 'partial' : 'completed',
      generatedAt: new Date().toISOString(),
      scheduledBackupIntervalMinutes: options.scheduledBackupIntervalMinutes,
      drillMaxAgeDays: options.drillMaxAgeDays,
      results
    };
  }

  function getPersistenceHealth() {
    const base = createRegistry().getPersistenceHealth();
    return {
      ...base,
      coordination: coordinator.health(),
      fencing: store.health()
    };
  }

  function getCoordinationStatus(tenantId = null) {
    const health = coordinator.health();
    return tenantId
      ? { ...health, tenant: coordinator.inspect(tenantId), latestFencingToken: store.latestFencingToken(tenantId) }
      : health;
  }

  function initialiseTenant(registry, tenantId) {
    registry.forTenant(tenantId);
    return registry;
  }

  return {
    coordinated: true,
    forTenant,
    listGovernanceEvents: (tenantId, options) => read(
      tenantId,
      (registry) => initialiseTenant(registry, tenantId).listGovernanceEvents(tenantId, options)
    ),
    verifyGovernanceIntegrity: (tenantId) => read(
      tenantId,
      (registry) => initialiseTenant(registry, tenantId).verifyGovernanceIntegrity(tenantId)
    ),
    createTenantBackup: (tenantId, options) => write(tenantId, (registry) => registry.createTenantBackup(tenantId, options)),
    listTenantBackups: (tenantId) => read(tenantId, (registry) => registry.listTenantBackups(tenantId)),
    verifyTenantBackup: (tenantId, backupId) => read(tenantId, (registry) => registry.verifyTenantBackup(tenantId, backupId)),
    replicateTenantBackup: (tenantId, backupId, options) => write(
      tenantId,
      (registry) => registry.replicateTenantBackup(tenantId, backupId, options)
    ),
    listTenantReplicas: (tenantId) => read(tenantId, (registry) => registry.listTenantReplicas(tenantId)),
    verifyTenantReplica: (tenantId, backupId) => read(tenantId, (registry) => registry.verifyTenantReplica(tenantId, backupId)),
    runRecoveryDrill: (tenantId, options) => write(tenantId, (registry) => registry.runRecoveryDrill(tenantId, options)),
    getResilienceStatus: (tenantId, options) => read(tenantId, (registry) => registry.getResilienceStatus(tenantId, options)),
    runResilienceCycle,
    restoreTenantBackup: (tenantId, backupId, options = {}) => options.dryRun === false
      ? write(tenantId, (registry) => registry.restoreTenantBackup(tenantId, backupId, options))
      : read(tenantId, (registry) => registry.restoreTenantBackup(tenantId, backupId, options)),
    getPersistenceHealth,
    getCoordinationStatus,
    tenantCount: () => seenTenants.size
  };
}

export function createRuntimeWorkforceAuditRegistry({ env = process.env } = {}) {
  const coordinator = createFileLeaseCoordinatorFromEnvironment(env);
  if (!coordinator.enabled) return createWorkforceAuditRegistry();

  const encryptedStore = createEncryptedSnapshotStoreFromEnvironment(env);
  const fencedStore = createFencedSnapshotStore({
    store: encryptedStore,
    directory: env.WORKFORCE_AUDIT_FENCED_DATA_DIR ?? `${encryptedStore.directory}/fenced`,
    retainedVersions: env.WORKFORCE_AUDIT_FENCED_VERSIONS
      ? Number(env.WORKFORCE_AUDIT_FENCED_VERSIONS)
      : 5
  });

  return createCoordinatedWorkforceAuditRegistry({
    coordinator,
    store: fencedStore,
    registryFactory: ({ store }) => createWorkforceAuditRegistry({ store })
  });
}

function createReadOnlyStore(store) {
  const unavailable = () => {
    const error = new Error('A tenant write lease is required for durable mutation.');
    error.code = 'WRITE_COORDINATION_REQUIRED';
    throw error;
  };
  return {
    ...store,
    save: unavailable,
    writeEncrypted: unavailable
  };
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
}
