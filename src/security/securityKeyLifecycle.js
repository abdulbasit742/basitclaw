import { resolve } from 'node:path';
import { createFileMutex } from './fileMutex.js';
import {
  createSecurityArchiveCodec,
  parseSecurityArchiveKeyring
} from './securityArchiveCodec.js';
import { createSecurityArchiveFilesystem } from './securityArchiveFilesystem.js';
import { parseSecurityAlertSigningKeyring } from './securityAlertCodec.js';

export function createSecurityArchiveKeyLifecycle({
  directory,
  encryptionKeys = null,
  primaryKeyId = null,
  encryptionKey = null,
  keyId = 'security-archive-v1',
  mutex = null,
  lockLeaseMs = 10_000,
  lockAcquireTimeoutMs = 2_000,
  lockRetryMs = 10,
  now = () => new Date()
} = {}) {
  if (!String(directory ?? '').trim()) throw new TypeError('A security archive directory is required for key lifecycle inspection.');
  const keys = encryptionKeys ?? (encryptionKey ? { [keyId]: encryptionKey } : null);
  if (!keys) throw new TypeError('Security archive key lifecycle inspection requires a keyring.');
  const primary = primaryKeyId ?? Object.keys(keys)[0];
  const codec = createSecurityArchiveCodec({ keys, primaryKeyId: primary });
  const singleKey = codec.keyIds.length === 1;
  const files = createSecurityArchiveFilesystem(directory);
  const lock = mutex ?? createFileMutex({
    directory: resolve(String(directory), 'locks'),
    leaseMs: lockLeaseMs,
    acquireTimeoutMs: lockAcquireTimeoutMs,
    retryMs: lockRetryMs,
    now
  });

  function inspectLocked() {
    const references = Object.fromEntries(codec.keyIds.map((id) => [id, {
      envelopes: 0,
      retentionAnchor: 0,
      pruneJournal: 0,
      total: 0
    }]));
    const missingKeyIds = new Set();
    const envelopeKeyIds = new Set();

    for (const { envelope } of files.readAll()) {
      envelopeKeyIds.add(String(envelope?.keyId ?? ''));
      try {
        codec.verifyEnvelope(envelope);
        codec.open(envelope);
        increment(references, envelope.keyId, 'envelopes');
      } catch (error) {
        if (error.keyId) missingKeyIds.add(error.keyId);
        else throw error;
      }
    }

    const anchorStored = files.readJson(files.anchorPath);
    if (anchorStored) {
      const { signature, ...anchor } = anchorStored;
      const signingKeyId = codec.identifySignedKey(anchor, signature, codec.signAnchor, anchor.signingKeyId ?? null);
      if (!signingKeyId) throw new Error('The security archive retention anchor cannot be verified by the configured keyring.');
      increment(references, signingKeyId, 'retentionAnchor');
    }

    const pruneStored = files.readJson(files.prunePlanPath);
    if (pruneStored) {
      const { signature, ...plan } = pruneStored;
      const signingKeyId = codec.identifySignedKey(plan, signature, codec.signPrunePlan, plan.signingKeyId ?? null);
      if (!signingKeyId) throw new Error('The security archive prune journal cannot be verified by the configured keyring.');
      increment(references, signingKeyId, 'pruneJournal');
    }

    for (const usage of Object.values(references)) {
      usage.total = usage.envelopes + usage.retentionAnchor + usage.pruneJournal;
    }
    for (const envelopeKeyId of envelopeKeyIds) {
      if (envelopeKeyId && !codec.hasKey(envelopeKeyId)) missingKeyIds.add(envelopeKeyId);
    }

    const retirementSafeKeyIds = codec.keyIds.filter((id) => id !== codec.primaryKeyId && references[id].total === 0);
    const retainedHistoricalKeyIds = codec.keyIds.filter((id) => id !== codec.primaryKeyId && references[id].total > 0);
    return {
      status: missingKeyIds.size > 0 ? 'unavailable' : singleKey ? 'legacy-single-key' : 'ready',
      mode: singleKey ? 'single-key' : 'keyring',
      primaryKeyId: codec.primaryKeyId,
      configuredKeyIds: codec.keyIds,
      configuredKeyCount: codec.keyIds.length,
      references,
      retainedHistoricalKeyIds,
      retirementSafeKeyIds,
      missingKeyIds: [...missingKeyIds],
      rotationReady: !singleKey && missingKeyIds.size === 0,
      inspectedAt: now().toISOString()
    };
  }

  function status() {
    try {
      return lock.withLock('security-archive', inspectLocked);
    } catch (error) {
      return {
        status: 'unavailable',
        mode: singleKey ? 'single-key' : 'keyring',
        primaryKeyId: codec.primaryKeyId,
        configuredKeyIds: codec.keyIds,
        configuredKeyCount: codec.keyIds.length,
        rotationReady: false,
        error: error.message,
        inspectedAt: now().toISOString()
      };
    }
  }

  function canRetire(value) {
    const requested = safeIdentifier(value, 'keyId');
    return lock.withLock('security-archive', () => {
      const snapshot = inspectLocked();
      if (!codec.hasKey(requested)) return { safe: false, keyId: requested, reason: 'key_not_configured', status: snapshot };
      if (requested === codec.primaryKeyId) return { safe: false, keyId: requested, reason: 'primary_key', status: snapshot };
      const usage = snapshot.references[requested];
      if (usage.total > 0) return { safe: false, keyId: requested, reason: 'retained_references', references: usage, status: snapshot };
      return { safe: true, keyId: requested, reason: 'no_retained_references', references: usage, status: snapshot };
    });
  }

  return { status, canRetire, primaryKeyId: codec.primaryKeyId, keyIds: codec.keyIds };
}

export function createSecurityKeyLifecycleFromEnvironment(env = process.env) {
  const archiveMode = String(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_MODE ?? 'disabled');
  const archiveKeys = parseSecurityArchiveKeyring(env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS)
    ?? legacyArchiveKeys(env);
  const archive = archiveMode === 'shared-file' && archiveKeys
    ? createSecurityArchiveKeyLifecycle({
        directory: env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_DIR ?? '.runtime-data/workforce-audit-security-archive',
        encryptionKeys: archiveKeys,
        primaryKeyId: env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID
          ?? env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY_ID
          ?? Object.keys(archiveKeys)[0],
        lockLeaseMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_LOCK_MS ?? 10_000),
        lockAcquireTimeoutMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_ACQUIRE_TIMEOUT_MS ?? 2_000),
        lockRetryMs: Number(env.WORKFORCE_AUDIT_SECURITY_CONTROL_RETRY_MS ?? 10)
      })
    : createDisabledLifecycle('archive');

  const alertSecrets = parseSecurityAlertSigningKeyring(env.WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS)
    ?? legacyAlertSecrets(env);
  const alertPrimary = env.WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID ?? 'security-alert-v1';
  const alert = alertSecrets
    ? createStaticSigningLifecycle({ keys: alertSecrets, primaryKeyId: alertPrimary })
    : createDisabledLifecycle('alert-signing');

  return {
    status: () => ({ archive: archive.status(), alertSigning: alert.status() }),
    archiveCanRetire: (keyId) => archive.canRetire(keyId),
    alertCanRetire: (keyId) => alert.canRetire(keyId)
  };
}

function createStaticSigningLifecycle({ keys, primaryKeyId }) {
  const configuredKeyIds = Object.keys(keys).map((id) => safeIdentifier(id, 'keyId'));
  const primary = safeIdentifier(primaryKeyId, 'primaryKeyId');
  if (!configuredKeyIds.includes(primary)) throw new TypeError('Security alert primary signing key ID is not present in the keyring.');
  const singleKey = configuredKeyIds.length === 1;
  const status = () => ({
    status: singleKey ? 'legacy-single-key' : 'ready',
    mode: singleKey ? 'single-key' : 'keyring',
    primaryKeyId: primary,
    configuredKeyIds,
    configuredKeyCount: configuredKeyIds.length,
    rotationReady: !singleKey,
    receiverOverlapRequired: true
  });
  const canRetire = (value) => {
    const requested = safeIdentifier(value, 'keyId');
    if (!configuredKeyIds.includes(requested)) return { safe: false, keyId: requested, reason: 'key_not_configured', status: status() };
    if (requested === primary) return { safe: false, keyId: requested, reason: 'primary_key', status: status() };
    return { safe: true, keyId: requested, reason: 'receiver_overlap_must_be_confirmed', status: status() };
  };
  return { status, canRetire };
}

function createDisabledLifecycle(kind) {
  const status = () => ({ status: 'disabled', mode: 'disabled', kind, rotationReady: false });
  return {
    status,
    canRetire: (keyId) => ({ safe: false, keyId: String(keyId ?? ''), reason: 'control_disabled', status: status() })
  };
}

function legacyArchiveKeys(env) {
  const value = env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY;
  if (!value) return null;
  const keyId = env.WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY_ID ?? 'security-archive-v1';
  return { [keyId]: value };
}

function legacyAlertSecrets(env) {
  const value = env.WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET;
  if (!value) return null;
  return { 'security-alert-v1': value };
}

function increment(references, keyId, field) {
  if (!references[keyId]) references[keyId] = { envelopes: 0, retentionAnchor: 0, pruneJournal: 0, total: 0 };
  references[keyId][field] += 1;
}

function safeIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}
