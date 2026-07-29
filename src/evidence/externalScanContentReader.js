import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  decryptEvidenceJson,
  parseEvidenceKeyring,
  readEvidenceJson,
  sha256,
  strictBase64,
  tenantEvidenceDirectory
} from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceNotFoundError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const CONTENT_FORMAT = 'basitclaw-workforce-audit-evidence';
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;

export function createExternalScanContentReader({ registry, keys, primaryKeyId } = {}) {
  if (!registry?.enabled || !registry.directory || typeof registry.get !== 'function') {
    throw new TypeError('An enabled evidence registry is required for external scan delivery.');
  }
  const keyring = parseEvidenceKeyring(keys, primaryKeyId);
  const root = resolve(registry.directory);

  function read(tenantId, evidenceId, { version = null } = {}) {
    const tenant = safeTenant(tenantId);
    const id = safeEvidenceId(evidenceId);
    const item = registry.get(tenant, id);
    if (!item || item.status === 'disposed') {
      throw new EvidenceConflictError('Disposed evidence cannot be transferred to an external scanner.', { evidenceId: id });
    }
    const selectedVersion = version === null ? item.currentVersion : integer(version, 'version', 1, item.currentVersion);
    const record = item.versions?.find((candidate) => candidate.version === selectedVersion);
    if (!record) throw new EvidenceNotFoundError(`${id}:v${selectedVersion}`);
    const path = resolve(
      tenantEvidenceDirectory(root, tenant),
      'items',
      id,
      `v${String(selectedVersion).padStart(6, '0')}.evidence`
    );
    if (!existsSync(path)) {
      throw new EvidenceIntegrityError('The immutable evidence content required for scanner delivery is missing.', {
        evidenceId: id,
        version: selectedVersion
      });
    }
    let envelope;
    try { envelope = readEvidenceJson(path); }
    catch (error) {
      throw new EvidenceIntegrityError('The immutable evidence content required for scanner delivery is unreadable.', {
        evidenceId: id,
        version: selectedVersion
      }, error);
    }
    const payload = decryptEvidenceJson(
      envelope,
      keyring,
      contentAad(tenant, id, selectedVersion),
      EvidenceIntegrityError
    );
    if (payload?.format !== CONTENT_FORMAT || payload.version !== selectedVersion
        || payload.tenantId !== tenant || payload.evidenceId !== id) {
      throw new EvidenceIntegrityError('Scanner delivery evidence identity verification failed.', {
        evidenceId: id,
        version: selectedVersion
      });
    }
    let content;
    try { content = strictBase64(payload.contentBase64, 'stored content'); }
    catch (error) {
      throw new EvidenceIntegrityError('Scanner delivery evidence content encoding is invalid.', {
        evidenceId: id,
        version: selectedVersion
      }, error);
    }
    const digest = sha256(content);
    if (digest !== record.sha256 || digest !== payload.sha256
        || content.length !== record.sizeBytes || content.length !== payload.sizeBytes) {
      throw new EvidenceIntegrityError('Scanner delivery evidence checksum verification failed.', {
        evidenceId: id,
        version: selectedVersion
      });
    }
    return Object.freeze({
      tenantId: tenant,
      evidenceId: id,
      version: selectedVersion,
      filename: record.filename ?? item.filename,
      mediaType: record.mediaType ?? item.mediaType,
      contentSha256: digest,
      sizeBytes: content.length,
      content
    });
  }

  return Object.freeze({ read, directory: root });
}

export function createExternalScanContentReaderFromEnvironment({ env = process.env, evidenceRegistry } = {}) {
  let keys;
  try { keys = JSON.parse(environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_KEYS)); }
  catch (error) {
    throw new EvidenceStoreError('Evidence encryption keys are invalid for scanner delivery.', {
      field: 'WORKFORCE_AUDIT_EVIDENCE_KEYS'
    }, error);
  }
  return createExternalScanContentReader({
    registry: evidenceRegistry,
    keys,
    primaryKeyId: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_PRIMARY_KEY_ID)
  });
}

function contentAad(tenant, evidenceId, version) {
  return `${CONTENT_FORMAT}:1:${tenant}:${evidenceId}:${version}`;
}
function safeEvidenceId(value) {
  const id = String(value ?? '').trim();
  if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId must be a valid EVD identifier.', { field: 'evidenceId' });
  return id;
}
function safeTenant(value) {
  const id = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(id)) throw new EvidenceValidationError('tenantId must be a safe identifier.', { field: 'tenantId' });
  return id;
}
function integer(value, field, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field });
  }
  return parsed;
}
function environmentValue(value) {
  const clean = typeof value === 'string' ? value.trim() : value;
  return clean === '' || clean === undefined || clean === null ? undefined : clean;
}
