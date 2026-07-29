import {
  BackupError,
  BackupIntegrityError,
  BackupNotFoundError,
  createBackupManagerFromEnvironment
} from '../persistence/backupManager.js';
import { createEncryptedSnapshotStoreFromEnvironment } from '../persistence/encryptedSnapshotStore.js';
import { createGovernanceLedger } from './governanceLedger.js';
import { createWorkforceAuditService, ValidationError } from './workforceAuditService.js';

export class RecoveryConflictError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'RecoveryConflictError';
    this.code = 'RECOVERY_CONFLICT';
    this.details = details;
  }
}

export function createWorkforceAuditRegistry({
  now = () => new Date(),
  ledger = createGovernanceLedger({ now }),
  store = createEncryptedSnapshotStoreFromEnvironment(),
  backupManager = null
} = {}) {
  const recovery = backupManager ?? resolveBackupManager(store);
  const services = new Map();

  function buildService(tenantId, initialState) {
    const persist = (state) => persistState(tenantId, state);
    return createWorkforceAuditService({
      now,
      tenantId,
      ledger,
      initialState,
      persist
    });
  }

  function forTenant(tenantId) {
    validateTenantId(tenantId);
    if (!services.has(tenantId)) {
      const snapshot = store.load(tenantId);
      ledger.importTenant(tenantId, snapshot?.governanceEvents ?? []);
      services.set(tenantId, buildService(tenantId, snapshot?.state ?? null));
    }
    return services.get(tenantId);
  }

  function persistState(tenantId, state) {
    store.save(tenantId, {
      schemaVersion: 1,
      tenantId,
      savedAt: now().toISOString(),
      state,
      governanceEvents: ledger.exportTenant(tenantId)
    });
  }

  function createTenantBackup(tenantId, {
    actor,
    reason,
    kind = 'manual'
  } = {}) {
    validateTenantId(tenantId);
    const safeActor = validateActor(actor);
    const safeReason = validateReason(reason);
    const service = forTenant(tenantId);
    persistState(tenantId, service.exportState());
    const backup = recovery.create(tenantId, { kind });
    const checkpoint = ledger.checkpoint(tenantId);
    try {
      ledger.append({
        tenantId,
        actor: safeActor,
        action: 'backup.created',
        entityType: 'backup',
        entityId: backup.backupId,
        metadata: {
          kind,
          reason: safeReason,
          checksumSha256: backup.checksumSha256,
          keyId: backup.keyId,
          prunedBackupIds: backup.prunedBackupIds
        }
      });
      persistState(tenantId, service.exportState());
      return backup;
    } catch (error) {
      ledger.rollbackTo(tenantId, checkpoint);
      try { recovery.remove(tenantId, backup.backupId); } catch {}
      throw error;
    }
  }

  function listTenantBackups(tenantId) {
    forTenant(tenantId);
    return recovery.list(tenantId);
  }

  function verifyTenantBackup(tenantId, backupId) {
    forTenant(tenantId);
    return recovery.verify(tenantId, backupId);
  }

  function restoreTenantBackup(tenantId, backupId, {
    actor,
    reason,
    expectedHeadHash,
    confirmation,
    dryRun = true
  } = {}) {
    validateTenantId(tenantId);
    const safeActor = validateActor(actor);
    const safeReason = validateReason(reason);
    const currentService = forTenant(tenantId);
    const currentIntegrity = ledger.verify(tenantId);
    if (expectedHeadHash === undefined || expectedHeadHash !== currentIntegrity.headHash) {
      throw new RecoveryConflictError('The governance head changed or was not supplied; restore was refused.', {
        expectedHeadHash,
        actualHeadHash: currentIntegrity.headHash
      });
    }

    const prepared = recovery.load(tenantId, backupId);
    const preview = {
      dryRun: dryRun !== false,
      backup: recovery.verify(tenantId, backupId),
      current: {
        engagementCount: currentService.exportState().engagements.length,
        findingCount: currentService.exportState().findings.length,
        governanceEventCount: currentIntegrity.checkedEvents,
        governanceHeadHash: currentIntegrity.headHash
      }
    };
    if (dryRun !== false) return preview;

    if (confirmation !== `RESTORE ${backupId}`) {
      throw new ValidationError(`confirmation must exactly equal RESTORE ${backupId}.`, {
        field: 'confirmation'
      });
    }

    const safetyBackup = createTenantBackup(tenantId, {
      actor: safeActor,
      reason: `Pre-restore safety copy: ${safeReason}`,
      kind: 'safety'
    });

    const previousService = services.get(tenantId);
    const previousState = previousService.exportState();
    const previousEvents = ledger.exportTenant(tenantId);
    const previousEnvelope = store.readEncrypted(tenantId);

    try {
      store.writeEncrypted(tenantId, prepared.serialized);
      ledger.replaceTenant(tenantId, prepared.snapshot.governanceEvents);
      const restoredService = buildService(tenantId, prepared.snapshot.state);
      services.set(tenantId, restoredService);
      const targetHeadHash = ledger.verify(tenantId).headHash;
      ledger.append({
        tenantId,
        actor: safeActor,
        action: 'backup.restored',
        entityType: 'backup',
        entityId: backupId,
        metadata: {
          reason: safeReason,
          safetyBackupId: safetyBackup.backupId,
          preRestoreGovernanceHeadHash: previousEvents.at(-1)?.hash ?? null,
          restoredGovernanceHeadHash: targetHeadHash
        }
      });
      persistState(tenantId, restoredService.exportState());
      return {
        dryRun: false,
        restoredBackupId: backupId,
        safetyBackupId: safetyBackup.backupId,
        governanceIntegrity: ledger.verify(tenantId),
        state: {
          engagementCount: restoredService.exportState().engagements.length,
          findingCount: restoredService.exportState().findings.length
        }
      };
    } catch (error) {
      try {
        if (previousEnvelope) store.writeEncrypted(tenantId, previousEnvelope.serialized);
        ledger.replaceTenant(tenantId, previousEvents);
        services.set(tenantId, buildService(tenantId, previousState));
      } catch (rollbackError) {
        throw new BackupError('The restore failed and automatic rollback was not fully successful.', {
          tenantId,
          backupId,
          safetyBackupId: safetyBackup.backupId,
          rollbackError: rollbackError.message
        }, error);
      }
      throw error;
    }
  }

  function getPersistenceHealth() {
    const persistence = store.health();
    return {
      ...persistence,
      backups: recovery.health()
    };
  }

  return {
    forTenant,
    listGovernanceEvents: (tenantId, options) => ledger.list(tenantId, options),
    verifyGovernanceIntegrity: (tenantId) => ledger.verify(tenantId),
    createTenantBackup,
    listTenantBackups,
    verifyTenantBackup,
    restoreTenantBackup,
    getPersistenceHealth,
    tenantCount: () => services.size
  };
}

function validateActor(value) {
  const actor = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(actor)) {
    throw new ValidationError('A valid recovery actor is required.', { field: 'actor' });
  }
  return actor;
}

function validateReason(value) {
  const reason = String(value ?? '').trim().replace(/[<>]/g, '');
  if (reason.length < 10 || reason.length > 500) {
    throw new ValidationError('Recovery reason must contain 10 to 500 characters.', { field: 'reason' });
  }
  return reason;
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) {
    throw new TypeError('tenantId must be a safe identifier.');
  }
}

function resolveBackupManager(store) {
  if (typeof store?.readEncrypted === 'function' && typeof store?.inspectEncrypted === 'function') {
    return createBackupManagerFromEnvironment(store);
  }
  const unavailable = () => {
    throw new BackupError('Encrypted backup operations are unavailable for the configured persistence store.', {
      operation: 'backup'
    });
  };
  return {
    create: unavailable,
    list: unavailable,
    load: unavailable,
    verify: unavailable,
    remove: () => false,
    health: () => ({
      status: 'unavailable',
      mode: 'encrypted-file-backup',
      retention: 0,
      tenantDirectoryCount: 0,
      error: 'The configured persistence store does not support encrypted backup operations.'
    })
  };
}

export { BackupError, BackupIntegrityError, BackupNotFoundError };
