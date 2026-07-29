import {
  BackupError,
  BackupIntegrityError,
  BackupNotFoundError,
  createBackupManagerFromEnvironment
} from '../persistence/backupManager.js';
import { createEncryptedSnapshotStoreFromEnvironment } from '../persistence/encryptedSnapshotStore.js';
import {
  createReplicaManagerFromEnvironment,
  ReplicaError,
  ReplicaIntegrityError,
  ReplicaNotFoundError
} from '../resilience/replicaManager.js';
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
  backupManager = null,
  replicaManager = null
} = {}) {
  const recovery = backupManager ?? resolveBackupManager(store);
  const replicas = replicaManager ?? createReplicaManagerFromEnvironment(store, recovery);
  const services = new Map();

  function buildService(tenantId, initialState) {
    const persist = (state) => persistState(tenantId, state);
    return createWorkforceAuditService({ now, tenantId, ledger, initialState, persist });
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

  function appendOperationalEvent(tenantId, input) {
    const service = forTenant(tenantId);
    const checkpoint = ledger.checkpoint(tenantId);
    try {
      const event = ledger.append({ tenantId, ...input });
      persistState(tenantId, service.exportState());
      return event;
    } catch (error) {
      ledger.rollbackTo(tenantId, checkpoint);
      throw error;
    }
  }

  function createTenantBackup(tenantId, { actor, reason, kind = 'manual' } = {}) {
    validateTenantId(tenantId);
    const safeActor = validateActor(actor);
    const safeReason = validateReason(reason);
    const service = forTenant(tenantId);
    persistState(tenantId, service.exportState());
    const backup = recovery.create(tenantId, { kind });
    try {
      appendOperationalEvent(tenantId, {
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
    } catch (error) {
      try { recovery.remove(tenantId, backup.backupId); } catch {}
      throw error;
    }

    let replication = { status: 'disabled', required: false };
    if (replicas.enabled) {
      try {
        const replicated = replicateTenantBackup(tenantId, backup.backupId, {
          actor: safeActor,
          reason: `Replicate ${kind} recovery point: ${safeReason}`
        });
        replication = { status: 'replicated', required: replicas.required, replica: replicated };
      } catch (error) {
        replication = {
          status: 'failed',
          required: replicas.required,
          code: error.code ?? 'REPLICA_UNAVAILABLE',
          error: error.message
        };
        try {
          appendOperationalEvent(tenantId, {
            actor: safeActor,
            action: 'backup.replication.failed',
            entityType: 'backup',
            entityId: backup.backupId,
            metadata: { reason: safeReason, code: replication.code }
          });
        } catch {}
      }
    }
    return { ...backup, replication };
  }

  function listTenantBackups(tenantId) {
    forTenant(tenantId);
    return recovery.list(tenantId);
  }

  function verifyTenantBackup(tenantId, backupId) {
    forTenant(tenantId);
    return recovery.verify(tenantId, backupId);
  }

  function replicateTenantBackup(tenantId, backupId, { actor, reason } = {}) {
    validateTenantId(tenantId);
    const safeActor = validateActor(actor);
    const safeReason = validateReason(reason);
    forTenant(tenantId);
    const replica = replicas.replicate(tenantId, backupId);
    try {
      appendOperationalEvent(tenantId, {
        actor: safeActor,
        action: 'backup.replicated',
        entityType: 'replica',
        entityId: backupId,
        metadata: {
          reason: safeReason,
          checksumSha256: replica.checksumSha256,
          replicatedAt: replica.replicatedAt,
          prunedReplicaIds: replica.prunedReplicaIds,
          idempotent: Boolean(replica.idempotent)
        }
      });
      return replica;
    } catch (error) {
      if (!replica.idempotent) {
        try { replicas.remove(tenantId, backupId); } catch {}
      }
      throw error;
    }
  }

  function listTenantReplicas(tenantId) {
    forTenant(tenantId);
    return replicas.list(tenantId);
  }

  function verifyTenantReplica(tenantId, backupId) {
    forTenant(tenantId);
    return replicas.verify(tenantId, backupId);
  }

  function runRecoveryDrill(tenantId, { actor, backupId = null } = {}) {
    validateTenantId(tenantId);
    const safeActor = validateActor(actor);
    forTenant(tenantId);
    const targetId = backupId ?? replicas.list(tenantId)[0]?.backupId;
    if (!targetId) throw new ReplicaNotFoundError('latest');
    const local = recovery.verify(tenantId, targetId);
    const replica = replicas.verify(tenantId, targetId);
    const summaryMatches = JSON.stringify(local.summary) === JSON.stringify(replica.summary);
    if (local.checksumSha256 !== replica.checksumSha256 || !summaryMatches) {
      throw new ReplicaIntegrityError('The replica does not match its source recovery point.', {
        tenantId,
        backupId: targetId,
        localChecksum: local.checksumSha256,
        replicaChecksum: replica.checksumSha256,
        summaryMatches
      });
    }
    const event = appendOperationalEvent(tenantId, {
      actor: safeActor,
      action: 'recovery.drill.completed',
      entityType: 'replica',
      entityId: targetId,
      metadata: {
        outcome: 'passed',
        checksumSha256: replica.checksumSha256,
        replicatedAt: replica.replicatedAt,
        engagementCount: replica.summary.engagementCount,
        findingCount: replica.summary.findingCount,
        governanceHeadHash: replica.summary.governanceHeadHash
      }
    });
    return {
      drillId: event.id,
      outcome: 'passed',
      completedAt: event.occurredAt,
      backupId: targetId,
      source: local,
      replica
    };
  }

  function getResilienceStatus(tenantId, { drillMaxAgeDays = 30 } = {}) {
    validateTenantId(tenantId);
    forTenant(tenantId);
    const backups = recovery.list(tenantId);
    const replicaList = replicas.list(tenantId);
    const replicaHealth = replicas.tenantHealth(tenantId);
    const latestDrill = ledger.exportTenant(tenantId)
      .filter((event) => event.action === 'recovery.drill.completed')
      .at(-1) ?? null;
    const drillAgeDays = latestDrill
      ? Math.max(0, Math.floor((now().getTime() - new Date(latestDrill.occurredAt).getTime()) / 86400000))
      : null;
    const drillStatus = !replicas.enabled
      ? 'disabled'
      : !latestDrill
        ? 'missing'
        : drillAgeDays > drillMaxAgeDays ? 'stale' : 'ready';
    const status = !replicas.enabled
      ? 'disabled'
      : replicaHealth.status === 'ready' && drillStatus === 'ready' ? 'ready' : 'attention';
    return {
      status,
      generatedAt: now().toISOString(),
      latestBackup: backups[0] ?? null,
      latestReplica: replicaList[0] ?? null,
      replicaHealth,
      drill: {
        status: drillStatus,
        maxAgeDays: drillMaxAgeDays,
        ageDays: drillAgeDays,
        latestEvent: latestDrill
      }
    };
  }

  function runResilienceCycle(tenantIds, {
    actor = 'system.scheduler',
    scheduledBackupIntervalMinutes = 1440,
    drillMaxAgeDays = 30
  } = {}) {
    const safeActor = validateActor(actor);
    const interval = validatePositiveInteger(scheduledBackupIntervalMinutes, 'scheduledBackupIntervalMinutes', 1, 525600);
    const maxDrillAge = validatePositiveInteger(drillMaxAgeDays, 'drillMaxAgeDays', 1, 3650);
    const results = [];
    for (const tenantId of [...new Set(tenantIds.map((value) => String(value)))]) {
      try {
        validateTenantId(tenantId);
        forTenant(tenantId);
        const backups = recovery.list(tenantId);
        const latestScheduled = backups.find((item) => item.kind === 'scheduled') ?? null;
        const backupAgeMinutes = latestScheduled
          ? Math.max(0, Math.floor((now().getTime() - new Date(latestScheduled.createdAt).getTime()) / 60000))
          : null;
        let backup = null;
        if (!latestScheduled || backupAgeMinutes >= interval) {
          backup = createTenantBackup(tenantId, {
            actor: safeActor,
            reason: 'Scheduled workforce-audit resilience recovery point',
            kind: 'scheduled'
          });
          if (backup.replication?.required && backup.replication.status === 'failed') {
            throw new ReplicaError('Required replication failed during the resilience cycle.', {
              tenantId,
              backupId: backup.backupId,
              code: backup.replication.code
            });
          }
        } else if (replicas.enabled && !replicas.list(tenantId).some((item) => item.backupId === backups[0]?.backupId)) {
          replicateTenantBackup(tenantId, backups[0].backupId, {
            actor: safeActor,
            reason: 'Repair missing replica for the latest recovery point'
          });
        }

        let drill = null;
        const statusBeforeDrill = getResilienceStatus(tenantId, { drillMaxAgeDays: maxDrillAge });
        if (replicas.enabled && ['missing', 'stale'].includes(statusBeforeDrill.drill.status) && statusBeforeDrill.latestReplica) {
          drill = runRecoveryDrill(tenantId, { actor: safeActor, backupId: statusBeforeDrill.latestReplica.backupId });
        }
        results.push({
          tenantId,
          status: 'completed',
          backupCreated: backup?.backupId ?? null,
          drillCompleted: drill?.drillId ?? null,
          resilience: getResilienceStatus(tenantId, { drillMaxAgeDays: maxDrillAge })
        });
      } catch (error) {
        results.push({ tenantId, status: 'failed', code: error.code ?? 'RESILIENCE_CYCLE_FAILED', error: error.message });
      }
    }
    return {
      status: results.some((item) => item.status === 'failed') ? 'partial' : 'completed',
      generatedAt: now().toISOString(),
      scheduledBackupIntervalMinutes: interval,
      drillMaxAgeDays: maxDrillAge,
      results
    };
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
      throw new ValidationError(`confirmation must exactly equal RESTORE ${backupId}.`, { field: 'confirmation' });
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
    const replicaSystem = replicas.health();
    const loadedTenantHealth = [...services.keys()].map((tenantId) => ({
      tenantId,
      ...replicas.tenantHealth(tenantId)
    }));
    const degradedTenantCount = loadedTenantHealth
      .filter((item) => !['ready', 'disabled', 'empty'].includes(item.status))
      .length;
    return {
      ...store.health(),
      backups: recovery.health(),
      replicas: {
        ...replicaSystem,
        readiness: !replicaSystem.enabled
          ? 'disabled'
          : degradedTenantCount > 0 ? 'degraded' : 'ready',
        degradedTenantCount,
        loadedTenantHealth
      }
    };
  }

  return {
    forTenant,
    listGovernanceEvents: (tenantId, options) => ledger.list(tenantId, options),
    verifyGovernanceIntegrity: (tenantId) => ledger.verify(tenantId),
    createTenantBackup,
    listTenantBackups,
    verifyTenantBackup,
    replicateTenantBackup,
    listTenantReplicas,
    verifyTenantReplica,
    runRecoveryDrill,
    getResilienceStatus,
    runResilienceCycle,
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

function validatePositiveInteger(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field });
  }
  return parsed;
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
    throw new BackupError('Encrypted backup operations are unavailable for the configured persistence store.', { operation: 'backup' });
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

export {
  BackupError,
  BackupIntegrityError,
  BackupNotFoundError,
  ReplicaError,
  ReplicaIntegrityError,
  ReplicaNotFoundError
};
