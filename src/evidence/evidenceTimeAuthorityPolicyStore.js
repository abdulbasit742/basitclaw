import {
  constants,
  createPublicKey,
  verify as verifyAsymmetric
} from 'node:crypto';
import { strictBase64 } from './evidenceCrypto.js';
import {
  EvidenceIntegrityError,
  EvidenceValidationError
} from './evidenceRegistry.js';
import {
  EvidenceTimeAttestationAuthenticationError,
  canonicalTimeAttestation
} from './evidenceTimeAttestationStore.js';

const ALGORITHMS = new Set(['ed25519', 'rsa-pss-sha256']);
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;

export class EvidenceTimeAuthorityPolicyError extends EvidenceTimeAttestationAuthenticationError {
  constructor(message = 'The time-authority key or policy is not trusted for this attestation.', details = {}) {
    super(message, details);
    this.name = 'EvidenceTimeAuthorityPolicyError';
    this.code = 'EVIDENCE_TIME_AUTHORITY_POLICY_NOT_TRUSTED';
  }
}

export class EvidenceTimeAuthorityPolicyEvaluationError extends EvidenceIntegrityError {
  constructor(message = 'Time-authority policy evaluation could not be completed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceTimeAuthorityPolicyEvaluationError';
    this.code = 'EVIDENCE_TIME_AUTHORITY_POLICY_EVALUATION_FAILED';
  }
}

export function createEvidenceTimeAuthorityPolicyStore({
  store,
  providers,
  expiryWarningDays = 30,
  maximumAttestationsPerArchive = 5000,
  now = () => new Date()
} = {}) {
  if (!store || typeof store.record !== 'function' || typeof store.verifyArchives !== 'function') {
    throw new TypeError('A time-attestation store is required.');
  }
  if (!store.enabled) return store;

  const authorityKeys = parseAuthorityKeys(providers);
  const warningMs = integer(expiryWarningDays, 'expiryWarningDays', 0, 3650) * 86_400_000;
  const archiveLimit = integer(maximumAttestationsPerArchive, 'maximumAttestationsPerArchive', 1, 5000);

  function record(input) {
    const authenticated = authenticateSubmission(input, authorityKeys);
    const decision = evaluatePolicy(authenticated, authorityKeys);
    if (!decision.trusted) {
      throw new EvidenceTimeAuthorityPolicyError('The time-authority key or policy is not trusted for this attestation.', {
        reason: decision.reason,
        providerId: authenticated.providerId,
        keyId: authenticated.keyId,
        timestamp: authenticated.timestamp,
        policyId: authenticated.policyId
      });
    }
    const result = store.record(input);
    return {
      ...result,
      attestation: {
        ...result.attestation,
        authorityPolicy: publicDecision(decision)
      }
    };
  }

  function list(tenantId, options = {}) {
    return store.list(tenantId, options).map((entry) => ({
      ...entry,
      authorityPolicy: publicDecision(evaluatePolicy(entry, authorityKeys))
    }));
  }

  function verifyArchive(tenantId, archiveId) {
    return verifyArchives(tenantId, [archiveId]).results.get(archiveIdentifier(archiveId));
  }

  function verifyArchives(tenantId, archiveIds = null) {
    const base = store.verifyArchives(tenantId, archiveIds);
    const results = new Map();
    for (const [archiveId, verification] of base.results) {
      const records = store.list(tenantId, { archiveId, limit: archiveLimit });
      if (verification.attestationCount > records.length) {
        throw new EvidenceTimeAuthorityPolicyEvaluationError(
          'The archive contains more attestations than the configured policy-evaluation limit.',
          {
            archiveId,
            attestationCount: verification.attestationCount,
            maximumAttestationsPerArchive: archiveLimit
          }
        );
      }
      const trustedProviders = new Set();
      const trustedKeys = new Set();
      const untrustedReasons = new Map();
      let trustedAttestations = 0;
      for (const record of records) {
        const decision = evaluatePolicy(record, authorityKeys);
        if (decision.trusted) {
          trustedAttestations += 1;
          trustedProviders.add(record.providerId);
          trustedKeys.add(`${record.providerId}/${record.keyId}`);
        } else {
          untrustedReasons.set(decision.reason, (untrustedReasons.get(decision.reason) ?? 0) + 1);
        }
      }
      results.set(archiveId, {
        ...verification,
        cryptographicQuorumSatisfied: verification.quorumSatisfied,
        policyCompliantAttestations: trustedAttestations,
        policyRejectedAttestations: records.length - trustedAttestations,
        policyCompliantDistinctProviders: trustedProviders.size,
        policyCompliantDistinctKeys: trustedKeys.size,
        minimumProviders: store.minimumProviders,
        quorumSatisfied: trustedProviders.size >= store.minimumProviders,
        providerIds: [...trustedProviders].sort(),
        policyRejectionReasons: Object.fromEntries(
          [...untrustedReasons].sort(([left], [right]) => left.localeCompare(right))
        )
      });
    }
    return { ...base, results };
  }

  function quorumForArchives(tenantId, archiveIds) {
    const batch = verifyArchives(tenantId, archiveIds);
    return new Map([...batch.results].map(([archiveId, verification]) => [
      archiveId,
      verification.quorumSatisfied ? verification : null
    ]));
  }

  function quorumForArchive(tenantId, archiveId) {
    return quorumForArchives(tenantId, [archiveId]).get(archiveIdentifier(archiveId)) ?? null;
  }

  function verifyTenant(tenantId) {
    const base = store.verifyTenant(tenantId);
    return {
      ...base,
      authorityPolicy: policyHealth(authorityKeys, store.minimumProviders, warningMs, now())
    };
  }

  function tenantStatus(tenantId) {
    const base = store.tenantStatus(tenantId);
    const policy = policyHealth(authorityKeys, store.minimumProviders, warningMs, now());
    return {
      ...base,
      status: combinedStatus(base.status, policy.status, store.requiredForDisposition),
      authorityPolicy: policy
    };
  }

  function health() {
    const base = store.health();
    const policy = policyHealth(authorityKeys, store.minimumProviders, warningMs, now());
    return {
      ...base,
      status: combinedStatus(base.status, policy.status, store.requiredForDisposition),
      authorityPolicy: policy,
      keyPolicyEnforced: true,
      maximumAttestationsPerArchive: archiveLimit
    };
  }

  return Object.freeze({
    ...store,
    record,
    list,
    verifyArchive,
    verifyArchives,
    quorumForArchive,
    quorumForArchives,
    verifyTenant,
    tenantStatus,
    health,
    authorityPolicyEnabled: true,
    maximumAttestationsPerArchive: archiveLimit
  });
}

export function createEvidenceTimeAuthorityPolicyStoreFromEnvironment({ store, env = process.env } = {}) {
  if (!store?.enabled) return store;
  const rawProviders = environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS);
  if (!rawProviders) throw new TypeError('WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS is required for authority key policy.');
  let providers;
  try { providers = JSON.parse(rawProviders); }
  catch (error) { throw new TypeError('WORKFORCE_AUDIT_EVIDENCE_NOTARY_PROVIDERS must be valid JSON.', { cause: error }); }
  return createEvidenceTimeAuthorityPolicyStore({
    store,
    providers,
    expiryWarningDays: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEY_EXPIRY_WARNING_DAYS) ?? 30,
    maximumAttestationsPerArchive: environmentValue(env.WORKFORCE_AUDIT_EVIDENCE_NOTARY_MAX_ATTESTATIONS_PER_ARCHIVE) ?? 5000
  });
}

function parseAuthorityKeys(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('Time-authority providers must be an object.');
  const authorities = new Map();
  for (const [providerId, provider] of Object.entries(raw)) {
    identifier(providerId, 'providerId');
    if (!provider || typeof provider !== 'object' || Array.isArray(provider)) throw new TypeError(`Provider ${providerId} must be an object.`);
    const rawKeys = provider.keys;
    if (!rawKeys || typeof rawKeys !== 'object' || Array.isArray(rawKeys) || !Object.keys(rawKeys).length) {
      throw new TypeError(`Provider ${providerId} must contain keys.`);
    }
    const keys = new Map();
    for (const [keyId, config] of Object.entries(rawKeys)) {
      identifier(keyId, 'keyId');
      if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Provider key ${providerId}/${keyId} must be an object.`);
      const algorithm = enumValue(config.algorithm, ALGORITHMS, 'algorithm');
      const publicKey = createPublicKey(String(config.publicKeyPem ?? ''));
      if (algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') {
        throw new TypeError(`Provider key ${providerId}/${keyId} must be Ed25519.`);
      }
      if (algorithm === 'rsa-pss-sha256') {
        if (!['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) throw new TypeError(`Provider key ${providerId}/${keyId} must be RSA.`);
        if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Provider key ${providerId}/${keyId} must be at least 2048 bits.`);
      }
      const validFrom = optionalIso(config.validFrom, 'validFrom');
      const validUntil = optionalIso(config.validUntil, 'validUntil');
      if (validFrom && validUntil && new Date(validFrom) >= new Date(validUntil)) {
        throw new TypeError(`Provider key ${providerId}/${keyId} validFrom must be before validUntil.`);
      }
      const allowedPolicyIds = optionalIdentifiers(config.allowedPolicyIds, 'allowedPolicyIds');
      keys.set(keyId, Object.freeze({
        providerId,
        keyId,
        algorithm,
        publicKey,
        validFrom,
        validUntil,
        allowedPolicyIds
      }));
    }
    authorities.set(providerId, keys);
  }
  if (!authorities.size || authorities.size > 20) throw new TypeError('Time-authority providers must contain 1 to 20 providers.');
  return authorities;
}

function authenticateSubmission(input, authorities) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new EvidenceValidationError('A valid time-attestation submission is required.');
  }
  const providerId = identifier(input.providerId, 'providerId');
  const keyId = identifier(input.keyId, 'keyId');
  const authority = authorities.get(providerId)?.get(keyId);
  if (!authority) {
    throw new EvidenceTimeAuthorityPolicyError('The time-authority provider or key is not configured.', {
      reason: 'unknown_authority_key'
    });
  }
  let signature;
  try { signature = strictBase64(input.signature, 'authority signature'); }
  catch {
    throw new EvidenceTimeAuthorityPolicyError('The authority signature is malformed.', {
      reason: 'signature_encoding'
    });
  }
  const data = Buffer.from(canonicalTimeAttestation(input), 'utf8');
  let valid = false;
  try {
    valid = authority.algorithm === 'ed25519'
      ? verifyAsymmetric(null, data, authority.publicKey, signature)
      : verifyAsymmetric('sha256', data, {
        key: authority.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO
      }, signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new EvidenceTimeAuthorityPolicyError('The authority signature is invalid.', {
      reason: 'signature_invalid'
    });
  }
  return input;
}

function evaluatePolicy(record, authorities) {
  const authority = authorities.get(record.providerId)?.get(record.keyId);
  if (!authority) return { trusted: false, reason: 'unknown_authority_key' };
  const timestamp = new Date(record.timestamp).getTime();
  if (!Number.isFinite(timestamp)) return { trusted: false, reason: 'timestamp_invalid' };
  if (authority.validFrom && timestamp < new Date(authority.validFrom).getTime()) {
    return { trusted: false, reason: 'key_not_yet_valid' };
  }
  if (authority.validUntil && timestamp > new Date(authority.validUntil).getTime()) {
    return { trusted: false, reason: 'key_expired_at_attestation' };
  }
  if (authority.allowedPolicyIds && !authority.allowedPolicyIds.has(record.policyId)) {
    return { trusted: false, reason: 'policy_not_allowed' };
  }
  return { trusted: true, reason: null };
}

function policyHealth(authorities, minimumProviders, warningMs, at) {
  const current = at.getTime();
  const providerStates = [];
  let activeProviders = 0;
  let activeKeys = 0;
  let pendingKeys = 0;
  let expiredKeys = 0;
  let expiringKeys = 0;
  for (const [providerId, keys] of authorities) {
    let providerActiveKeys = 0;
    for (const key of keys.values()) {
      const state = currentKeyState(key, current, warningMs);
      if (state.active) {
        activeKeys += 1;
        providerActiveKeys += 1;
      }
      if (state.pending) pendingKeys += 1;
      if (state.expired) expiredKeys += 1;
      if (state.expiring) expiringKeys += 1;
    }
    if (providerActiveKeys > 0) activeProviders += 1;
    providerStates.push({ providerId, configuredKeys: keys.size, activeKeys: providerActiveKeys });
  }
  const quorumAvailable = activeProviders >= minimumProviders;
  return {
    status: !quorumAvailable ? 'unavailable' : expiringKeys || expiredKeys || pendingKeys ? 'attention' : 'ready',
    minimumProviders,
    configuredProviders: authorities.size,
    activeProviders,
    quorumAvailable,
    activeKeys,
    pendingKeys,
    expiredKeys,
    expiringKeys,
    providers: providerStates.sort((left, right) => left.providerId.localeCompare(right.providerId))
  };
}

function currentKeyState(key, current, warningMs) {
  const validFrom = key.validFrom ? new Date(key.validFrom).getTime() : null;
  const validUntil = key.validUntil ? new Date(key.validUntil).getTime() : null;
  const pending = Boolean(validFrom !== null && validFrom > current);
  const expired = Boolean(validUntil !== null && validUntil < current);
  const active = !pending && !expired;
  const expiring = Boolean(active && validUntil !== null && validUntil - current <= warningMs);
  return { active, pending, expired, expiring };
}

function combinedStatus(baseStatus, policyStatus, requiredForDisposition) {
  if (baseStatus === 'unavailable') return 'unavailable';
  if (policyStatus === 'unavailable') return requiredForDisposition ? 'unavailable' : 'attention';
  if (policyStatus === 'attention' && baseStatus === 'ready') return 'attention';
  return baseStatus;
}

function publicDecision(decision) {
  return { trusted: decision.trusted, reason: decision.reason };
}

function optionalIdentifiers(value, field) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || !value.length || value.length > 100) throw new TypeError(`${field} must contain 1 to 100 identifiers.`);
  return new Set(value.map((entry) => identifier(entry, field)));
}
function optionalIso(value, field) {
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) throw new TypeError(`${field} must be a valid ISO date.`);
  return date.toISOString();
}
function archiveIdentifier(value) { const id = String(value ?? ''); if (!ARCHIVE_ID.test(id)) throw new EvidenceValidationError('archiveId is invalid.', { field: 'archiveId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new TypeError(`${field} must be one of ${[...allowed].join(', ')}.`); return text; }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`); return parsed; }
function environmentValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
