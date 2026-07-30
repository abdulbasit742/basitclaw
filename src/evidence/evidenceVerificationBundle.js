import {
  constants,
  createPrivateKey,
  createPublicKey,
  sign as signAsymmetric,
  verify as verifyAsymmetric
} from 'node:crypto';
import { sha256, strictBase64 } from './evidenceCrypto.js';
import {
  EvidenceConflictError,
  EvidenceIntegrityError,
  EvidenceStoreError,
  EvidenceValidationError
} from './evidenceRegistry.js';

const FORMAT = 'basitclaw-portable-evidence-verification-bundle';
const EVIDENCE_ID = /^EVD-[a-f0-9]{32}$/;
const ARCHIVE_ID = /^ARC-[a-f0-9]{32}$/;
const BUNDLE_ID = /^EVB-[a-f0-9]{32}$/;
const HASH = /^[a-f0-9]{64}$/;
const MODES = new Set(['disabled', 'signed']);
const PROFILES = new Set(['minimal', 'audit']);
const ALGORITHMS = new Set(['ed25519', 'rsa-pss-sha256']);
const FORBIDDEN_PROOF_KEYS = new Set([
  'content', 'contentBase64', 'plaintext', 'rawContent', 'wrappedKey',
  'claimToken', 'privateKey', 'secret', 'password', 'apiKey', 'accessToken'
]);

export class EvidenceVerificationBundleError extends EvidenceStoreError {
  constructor(message = 'The portable verification-bundle service is unavailable.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceVerificationBundleError';
    this.code = 'EVIDENCE_VERIFICATION_BUNDLE_UNAVAILABLE';
  }
}

export class EvidenceVerificationBundleIntegrityError extends EvidenceIntegrityError {
  constructor(message = 'Portable verification-bundle verification failed.', details = {}, cause = null) {
    super(message, details, cause);
    this.name = 'EvidenceVerificationBundleIntegrityError';
    this.code = 'EVIDENCE_VERIFICATION_BUNDLE_INTEGRITY_FAILED';
  }
}

export function createEvidenceVerificationBundleService({
  registry,
  mode = 'disabled',
  signingKeys,
  primarySigningKeyId,
  maximumAgeDays = 30,
  requireTimeQuorum = true,
  now = () => new Date()
} = {}) {
  if (!registry || typeof registry.verifyEvidencePreservation !== 'function'
      || typeof registry.verifyEvidenceTimeAttestations !== 'function') {
    throw new TypeError('A time-attestation-aware evidence registry is required.');
  }
  const selectedMode = enumValue(mode, MODES, 'mode');
  if (selectedMode === 'disabled') return disabledService();
  const signing = parseSigningKeyring(signingKeys, primarySigningKeyId);
  const ageDays = integer(maximumAgeDays, 'maximumAgeDays', 1, 3650);
  const quorumRequired = booleanValue(requireTimeQuorum, 'requireTimeQuorum');

  function create(tenantId, evidenceId, input = {}, context = {}) {
    const tenant = identifier(tenantId, 'tenantId');
    const evidence = evidenceIdentifier(evidenceId);
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid verification-bundle request is required.');
    }
    const item = registry.get(tenant, evidence);
    if (item.status === 'disposed') {
      throw new EvidenceConflictError('Disposed evidence cannot be exported as a new verification bundle.', { evidenceId: evidence });
    }
    const versionNumber = input.version === undefined || input.version === null
      ? item.currentVersion
      : integer(input.version, 'version', 1, 1_000_000);
    const version = item.versions?.find((entry) => entry.version === versionNumber);
    if (!version) throw new EvidenceValidationError('The requested evidence version does not exist.', { field: 'version' });
    if (input.confirmation !== `EXPORT PROOF ${evidence} V${versionNumber}`) {
      throw new EvidenceValidationError(`confirmation must be exactly EXPORT PROOF ${evidence} V${versionNumber}.`, {
        field: 'confirmation'
      });
    }
    const profile = enumValue(input.profile ?? 'minimal', PROFILES, 'profile');
    const recipientRef = safeText(input.recipientRef, 'recipientRef', 3, 128);
    const purpose = safeText(input.purpose, 'purpose', 10, 500);
    const actor = identifier(context.actor, 'actor');
    const receipt = registry.evidencePreservationStore?.verifiedForVersion?.(
      tenant, evidence, versionNumber, version.sha256, item.retentionUntil
    );
    if (!receipt) {
      throw new EvidenceConflictError('A verified immutable preservation receipt is required before proof export.', {
        evidenceId: evidence,
        version: versionNumber,
        code: 'EVIDENCE_PRESERVATION_REQUIRED'
      });
    }
    const preservationVerification = registry.verifyEvidencePreservation(tenant, receipt.archiveId);
    const timeVerification = registry.verifyEvidenceTimeAttestations(tenant, receipt.archiveId);
    if (quorumRequired && !timeVerification.quorumSatisfied) {
      throw new EvidenceConflictError('Independent time-attestation quorum is required before proof export.', {
        evidenceId: evidence,
        version: versionNumber,
        archiveId: receipt.archiveId,
        distinctProviders: timeVerification.distinctProviders,
        minimumProviders: timeVerification.minimumProviders,
        code: 'EVIDENCE_TIME_ATTESTATION_REQUIRED'
      });
    }
    const attestations = registry.evidenceTimeAttestations(tenant, receipt.archiveId, { limit: 5000 });
    const generatedAt = now().toISOString();
    const expiresAt = requestedExpiry(input.expiresAt, generatedAt, ageDays);
    const proof = buildProof({
      profile,
      item,
      version,
      receipt,
      preservationVerification,
      timeVerification,
      attestations
    });
    assertNoRawContent(proof);
    const proofSha256 = sha256(stableStringify(proof));
    const unsigned = {
      format: FORMAT,
      version: 1,
      bundleId: null,
      tenantRef: sha256(tenant),
      evidenceId: evidence,
      evidenceVersion: versionNumber,
      archiveId: receipt.archiveId,
      profile,
      generatedAt,
      expiresAt,
      recipientRef,
      purposeDigest: sha256(purpose),
      actorRef: sha256(actor),
      proofSha256,
      proof
    };
    unsigned.bundleId = `EVB-${sha256(stableStringify({ ...unsigned, bundleId: undefined })).slice(0, 32)}`;
    const bundle = signBundle(unsigned, signing);
    return {
      created: true,
      bundle,
      summary: {
        bundleId: bundle.bundleId,
        evidenceId: bundle.evidenceId,
        evidenceVersion: bundle.evidenceVersion,
        archiveId: bundle.archiveId,
        profile: bundle.profile,
        recipientRef: bundle.recipientRef,
        generatedAt: bundle.generatedAt,
        expiresAt: bundle.expiresAt,
        proofSha256: bundle.proofSha256,
        signingKeyId: bundle.signature.keyId,
        signingAlgorithm: bundle.signature.algorithm,
        publicKeySha256: bundle.signature.publicKeySha256
      }
    };
  }

  function verify(bundle, options = {}) {
    return verifyPortableEvidenceBundle(bundle, signing.publicKeys, options);
  }

  function health() {
    return {
      status: 'ready',
      enabled: true,
      mode: 'signed-stateless-portable-verification-bundles',
      stateless: true,
      rawEvidenceContentIncluded: false,
      requireTimeQuorum: quorumRequired,
      maximumAgeDays: ageDays,
      profiles: [...PROFILES],
      signingKeyCount: signing.keys.size,
      primarySigningKeyId: signing.primaryKeyId,
      publicSigningKeys: exportPublicKeys(signing)
    };
  }

  return Object.freeze({
    mode: selectedMode,
    enabled: true,
    create,
    verify,
    health,
    publicSigningKeys: Object.freeze(exportPublicKeys(signing))
  });
}

export function createEvidenceVerificationBundleServiceFromEnvironment({ env = process.env, registry } = {}) {
  try {
    const mode = envValue(env.WORKFORCE_AUDIT_EVIDENCE_BUNDLE_MODE) ?? 'disabled';
    if (mode === 'disabled') return createEvidenceVerificationBundleService({ registry, mode });
    const rawKeys = envValue(env.WORKFORCE_AUDIT_EVIDENCE_BUNDLE_SIGNING_KEYS);
    const primary = envValue(env.WORKFORCE_AUDIT_EVIDENCE_BUNDLE_PRIMARY_SIGNING_KEY_ID);
    if (!rawKeys || !primary) {
      throw new EvidenceVerificationBundleError('Dedicated verification-bundle signing keys and a primary key ID are required.', {
        reason: 'missing_bundle_signing_configuration'
      });
    }
    return createEvidenceVerificationBundleService({
      registry,
      mode,
      signingKeys: JSON.parse(rawKeys),
      primarySigningKeyId: primary,
      maximumAgeDays: envValue(env.WORKFORCE_AUDIT_EVIDENCE_BUNDLE_MAX_AGE_DAYS) ?? 30,
      requireTimeQuorum: parseBoolean(envValue(env.WORKFORCE_AUDIT_EVIDENCE_BUNDLE_REQUIRE_TIME_QUORUM) ?? true)
    });
  } catch (error) {
    if (error instanceof EvidenceVerificationBundleError) throw error;
    throw new EvidenceVerificationBundleError('Verification-bundle configuration is invalid.', {
      reason: error?.code ?? 'invalid_configuration'
    }, error);
  }
}

export function verifyPortableEvidenceBundle(bundle, trustedKeys, { allowExpired = false, now = () => new Date() } = {}) {
  try {
    if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)
        || bundle.format !== FORMAT || bundle.version !== 1
        || !BUNDLE_ID.test(String(bundle.bundleId ?? ''))
        || !EVIDENCE_ID.test(String(bundle.evidenceId ?? ''))
        || !ARCHIVE_ID.test(String(bundle.archiveId ?? ''))
        || !HASH.test(String(bundle.tenantRef ?? ''))
        || !HASH.test(String(bundle.purposeDigest ?? ''))
        || !HASH.test(String(bundle.actorRef ?? ''))
        || !HASH.test(String(bundle.proofSha256 ?? ''))
        || !PROFILES.has(String(bundle.profile ?? ''))) {
      throw new Error('invalid_bundle_identity');
    }
    const generatedAt = isoDate(bundle.generatedAt, 'generatedAt');
    const expiresAt = isoDate(bundle.expiresAt, 'expiresAt');
    if (new Date(expiresAt) <= new Date(generatedAt)) throw new Error('invalid_expiry');
    if (!allowExpired && now() >= new Date(expiresAt)) throw new Error('bundle_expired');
    if (!bundle.proof || typeof bundle.proof !== 'object' || Array.isArray(bundle.proof)) {
      throw new Error('invalid_proof');
    }
    assertNoRawContent(bundle.proof);
    if (sha256(stableStringify(bundle.proof)) !== bundle.proofSha256) throw new Error('proof_digest_mismatch');
    const signature = bundle.signature;
    if (!signature || typeof signature !== 'object') throw new Error('missing_signature');
    const keyring = normaliseTrustedKeys(trustedKeys);
    const trusted = keyring.get(identifier(signature.keyId, 'keyId'));
    if (!trusted || trusted.algorithm !== signature.algorithm
        || trusted.publicKeySha256 !== signature.publicKeySha256) {
      throw new Error('untrusted_signing_key');
    }
    const { signature: _signature, ...unsigned } = bundle;
    const canonical = stableStringify(unsigned);
    const supplied = strictBase64(signature.value, 'bundle signature');
    const valid = trusted.algorithm === 'ed25519'
      ? verifyAsymmetric(null, Buffer.from(canonical), trusted.publicKey, supplied)
      : verifyAsymmetric('sha256', Buffer.from(canonical), {
        key: trusted.publicKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: constants.RSA_PSS_SALTLEN_AUTO
      }, supplied);
    if (!valid) throw new Error('signature_invalid');
    return {
      valid: true,
      bundleId: bundle.bundleId,
      evidenceId: bundle.evidenceId,
      evidenceVersion: bundle.evidenceVersion,
      archiveId: bundle.archiveId,
      profile: bundle.profile,
      recipientRef: bundle.recipientRef,
      generatedAt,
      expiresAt,
      proofSha256: bundle.proofSha256,
      signingKeyId: signature.keyId,
      signingAlgorithm: signature.algorithm,
      publicKeySha256: signature.publicKeySha256,
      expired: now() >= new Date(expiresAt)
    };
  } catch (error) {
    if (error instanceof EvidenceVerificationBundleIntegrityError) throw error;
    throw new EvidenceVerificationBundleIntegrityError('Portable verification-bundle verification failed.', {
      reason: error?.message ?? 'verification_failed',
      bundleId: bundle?.bundleId ?? null
    }, error);
  }
}

function buildProof({ profile, item, version, receipt, preservationVerification, timeVerification, attestations }) {
  const proof = {
    evidence: {
      evidenceId: item.evidenceId,
      version: version.version,
      contentSha256: version.sha256,
      sizeBytes: version.sizeBytes,
      mediaType: version.mediaType ?? item.mediaType,
      retentionUntil: item.retentionUntil,
      status: item.status,
      screeningStatus: version.screeningStatus ?? item.screeningStatus ?? null
    },
    preservation: {
      archiveId: receipt.archiveId,
      receiptId: receipt.receiptId,
      contentSha256: receipt.contentSha256,
      sizeBytes: receipt.sizeBytes,
      objectEnvelopeSha256: receipt.objectEnvelopeSha256,
      retentionUntil: receipt.retentionUntil,
      legalHoldActive: receipt.legalHoldActive,
      archivedAt: receipt.archivedAt,
      immutabilityMode: receipt.immutabilityMode,
      signingKeyId: receipt.signingKeyId,
      signature: receipt.signature,
      verified: Boolean(preservationVerification?.valid)
    },
    timeAttestations: {
      valid: Boolean(timeVerification?.valid),
      quorumSatisfied: Boolean(timeVerification?.quorumSatisfied),
      minimumProviders: timeVerification?.minimumProviders ?? 0,
      distinctProviders: timeVerification?.distinctProviders ?? 0,
      providerIds: [...(timeVerification?.providerIds ?? [])],
      records: attestations.map((entry) => ({
        attestationId: entry.attestationId,
        providerId: entry.providerId,
        keyId: entry.keyId,
        timestamp: entry.timestamp,
        policyId: entry.policyId,
        receiptSha256: entry.receiptSha256,
        objectEnvelopeSha256: entry.objectEnvelopeSha256,
        sequence: entry.sequence,
        previousHash: entry.previousHash,
        hash: entry.hash
      }))
    }
  };
  if (profile === 'audit') {
    proof.auditContext = {
      filename: version.filename ?? item.filename,
      createdAt: item.createdAt ?? null,
      updatedAt: item.updatedAt ?? null,
      currentVersion: item.currentVersion,
      versionCount: item.versions?.length ?? 0,
      legalHoldActive: Boolean(item.legalHold?.active),
      preservationReceiptDigest: sha256(stableStringify(receipt))
    };
  }
  return proof;
}

function signBundle(unsigned, keyring) {
  const keyId = keyring.primaryKeyId;
  const key = keyring.keys.get(keyId);
  const canonical = stableStringify(unsigned);
  const value = key.algorithm === 'ed25519'
    ? signAsymmetric(null, Buffer.from(canonical), key.privateKey)
    : signAsymmetric('sha256', Buffer.from(canonical), {
      key: key.privateKey,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32
    });
  return {
    ...unsigned,
    signature: {
      keyId,
      algorithm: key.algorithm,
      publicKeySha256: key.publicKeySha256,
      value: value.toString('base64')
    }
  };
}

function parseSigningKeyring(raw, primaryKeyId) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('Verification-bundle signing keys must be an object.');
  }
  const entries = Object.entries(raw);
  if (!entries.length || entries.length > 20) throw new TypeError('Verification-bundle signing keys must contain 1 to 20 entries.');
  const keys = new Map();
  const publicKeys = new Map();
  for (const [keyId, config] of entries) {
    identifier(keyId, 'keyId');
    if (!config || typeof config !== 'object' || Array.isArray(config)) throw new TypeError(`Signing key ${keyId} must be an object.`);
    const algorithm = enumValue(config.algorithm, ALGORITHMS, 'algorithm');
    const privateKey = createPrivateKey(String(config.privateKeyPem ?? ''));
    const publicKey = createPublicKey(privateKey);
    if (algorithm === 'ed25519' && privateKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Signing key ${keyId} must be Ed25519.`);
    if (algorithm === 'rsa-pss-sha256') {
      if (!['rsa', 'rsa-pss'].includes(privateKey.asymmetricKeyType)) throw new TypeError(`Signing key ${keyId} must be RSA.`);
      if ((privateKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) throw new TypeError(`Signing key ${keyId} must be at least 2048 bits.`);
    }
    const publicKeySha256 = sha256(publicKey.export({ format: 'der', type: 'spki' }));
    keys.set(keyId, Object.freeze({ algorithm, privateKey, publicKey, publicKeySha256 }));
    publicKeys.set(keyId, Object.freeze({ algorithm, publicKey, publicKeySha256 }));
  }
  const primary = identifier(primaryKeyId, 'primarySigningKeyId');
  if (!keys.has(primary)) throw new TypeError('The primary verification-bundle signing key is not present.');
  return Object.freeze({ keys, publicKeys, primaryKeyId: primary });
}

function normaliseTrustedKeys(raw) {
  if (raw instanceof Map) return raw;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new TypeError('A trusted public-key ring is required.');
  const keys = new Map();
  for (const [keyId, config] of Object.entries(raw)) {
    const id = identifier(keyId, 'keyId');
    const algorithm = enumValue(config?.algorithm, ALGORITHMS, 'algorithm');
    const publicKey = createPublicKey(String(config?.publicKeyPem ?? ''));
    if (algorithm === 'ed25519' && publicKey.asymmetricKeyType !== 'ed25519') throw new TypeError(`Trusted key ${id} must be Ed25519.`);
    if (algorithm === 'rsa-pss-sha256' && !['rsa', 'rsa-pss'].includes(publicKey.asymmetricKeyType)) throw new TypeError(`Trusted key ${id} must be RSA.`);
    const publicKeySha256 = sha256(publicKey.export({ format: 'der', type: 'spki' }));
    if (config.publicKeySha256 && config.publicKeySha256 !== publicKeySha256) throw new Error('public_key_fingerprint_mismatch');
    keys.set(id, Object.freeze({ algorithm, publicKey, publicKeySha256 }));
  }
  return keys;
}

function exportPublicKeys(keyring) {
  return Object.fromEntries([...keyring.publicKeys].map(([keyId, entry]) => [keyId, {
    algorithm: entry.algorithm,
    publicKeyPem: entry.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    publicKeySha256: entry.publicKeySha256
  }]));
}

function requestedExpiry(value, generatedAt, maximumAgeDays) {
  const latest = new Date(new Date(generatedAt).getTime() + maximumAgeDays * 86400000);
  if (value === undefined || value === null || value === '') return latest.toISOString();
  const requested = new Date(isoDate(value, 'expiresAt'));
  if (requested <= new Date(generatedAt)) throw new EvidenceValidationError('expiresAt must be after bundle generation.', { field: 'expiresAt' });
  if (requested > latest) throw new EvidenceValidationError('expiresAt exceeds the configured maximum bundle age.', { field: 'expiresAt', maximumAgeDays });
  return requested.toISOString();
}

function assertNoRawContent(value, path = 'proof') {
  if (Array.isArray(value)) return value.forEach((entry, index) => assertNoRawContent(entry, `${path}[${index}]`));
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_PROOF_KEYS.has(key)) {
      throw new EvidenceValidationError(`Portable proof field ${path}.${key} is forbidden.`, { field: `${path}.${key}` });
    }
    assertNoRawContent(entry, `${path}.${key}`);
  }
}

function disabledService() {
  const status = Object.freeze({ status: 'disabled', enabled: false, mode: 'disabled', rawEvidenceContentIncluded: false });
  return Object.freeze({
    mode: 'disabled', enabled: false,
    create() { throw new EvidenceConflictError('Portable verification bundles are disabled.'); },
    verify() { throw new EvidenceConflictError('Portable verification bundles are disabled.'); },
    health() { return status; },
    publicSigningKeys: Object.freeze({})
  });
}

function evidenceIdentifier(value) { const id = String(value ?? ''); if (!EVIDENCE_ID.test(id)) throw new EvidenceValidationError('evidenceId is invalid.', { field: 'evidenceId' }); return id; }
function identifier(value, field) { const text = String(value ?? '').trim(); if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) throw new EvidenceValidationError(`${field} is invalid.`, { field }); return text; }
function safeText(value, field, minimum, maximum) { const text = String(value ?? '').trim(); if (text.length < minimum || text.length > maximum || /[\r\n\0]/.test(text)) throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} safe characters.`, { field }); return text; }
function isoDate(value, field) { const date = new Date(String(value ?? '')); if (Number.isNaN(date.getTime())) throw new EvidenceValidationError(`${field} must be a valid ISO date.`, { field }); return date.toISOString(); }
function integer(value, field, minimum, maximum) { const parsed = Number(value); if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new EvidenceValidationError(`${field} must be an integer from ${minimum} to ${maximum}.`, { field }); return parsed; }
function enumValue(value, allowed, field) { const text = String(value ?? ''); if (!allowed.has(text)) throw new EvidenceValidationError(`${field} must be one of ${[...allowed].join(', ')}.`, { field }); return text; }
function booleanValue(value, field) { if (typeof value !== 'boolean') throw new TypeError(`${field} must be true or false.`); return value; }
function parseBoolean(value) { if (typeof value === 'boolean') return value; if (value === 'true') return true; if (value === 'false') return false; throw new TypeError('Boolean environment value must be true or false.'); }
function envValue(value) { const clean = typeof value === 'string' ? value.trim() : value; return clean === '' || clean === undefined || clean === null ? undefined : clean; }
export function stableStringify(value) { if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`; if (value && typeof value === 'object') return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`; return JSON.stringify(value); }
