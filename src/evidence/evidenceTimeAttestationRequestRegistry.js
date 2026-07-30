import { EvidenceConflictError, EvidenceValidationError } from './evidenceRegistry.js';
import { createEvidenceAssuranceBundleRegistryFromEnvironment } from './evidenceAssuranceBundleRegistry.js';
import {
  createEvidenceTimeAttestationRequestOutbox,
  createEvidenceTimeAttestationRequestOutboxFromEnvironment
} from './evidenceTimeAttestationRequestOutbox.js';

export function createEvidenceTimeAttestationRequestRegistry({
  registry,
  notaryRequests = createEvidenceTimeAttestationRequestOutbox({ mode: 'disabled' })
} = {}) {
  if (!registry || typeof registry.timeAttestationChallenge !== 'function'
      || typeof registry.recordTimeAttestation !== 'function') {
    throw new TypeError('A time-attestation-aware evidence registry is required.');
  }
  if (!notaryRequests || typeof notaryRequests.queue !== 'function') {
    throw new TypeError('An evidence-notary request outbox is required.');
  }

  function queueTimeAttestationRequest(tenantId, archiveId, input = {}, context = {}) {
    if (!notaryRequests.enabled) throw new EvidenceConflictError('Evidence-notary request delivery is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid evidence-notary request is required.');
    }
    const providerId = identifier(input.providerId, 'providerId');
    const confirmation = `REQUEST NOTARY ${archiveId} ${providerId}`;
    if (input.confirmation !== confirmation) {
      throw new EvidenceValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    }
    const purpose = cleanText(input.purpose, 'purpose', 10, 500);
    const challenge = registry.timeAttestationChallenge(tenantId, archiveId);
    const existing = registry.evidenceTimeAttestations(tenantId, archiveId, {
      providerId,
      limit: 1
    });
    if (existing.length) {
      return {
        queued: false,
        duplicate: true,
        alreadyAttested: true,
        attestation: existing[0],
        job: null
      };
    }
    return notaryRequests.queue(challenge, providerId, {
      actor: context.actor,
      purpose
    });
  }

  function requeueTimeAttestationRequest(tenantId, jobId, input = {}, context = {}) {
    if (!notaryRequests.enabled) throw new EvidenceConflictError('Evidence-notary request delivery is disabled.');
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      throw new EvidenceValidationError('A valid evidence-notary requeue request is required.');
    }
    const confirmation = `REQUEUE NOTARY ${jobId}`;
    if (input.confirmation !== confirmation) {
      throw new EvidenceValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    }
    return notaryRequests.requeue(tenantId, jobId, {
      actor: context.actor,
      purpose: cleanText(input.purpose, 'purpose', 10, 500)
    });
  }

  function claimTimeAttestationRequests(input) {
    return notaryRequests.claimSigned(input);
  }

  function acknowledgeTimeAttestationRequest(jobId, input) {
    return notaryRequests.acknowledgeSigned(jobId, input);
  }

  function failTimeAttestationRequest(jobId, input) {
    return notaryRequests.failSigned(jobId, input);
  }

  function recordTimeAttestation(input) {
    const recorded = registry.recordTimeAttestation(input);
    const requestCompletion = notaryRequests.completeFromAttestation(input, recorded.attestation);
    return { ...recorded, requestCompletion };
  }

  function evidenceTimeAttestationRequests(tenantId, archiveId = null, options = {}) {
    if (archiveId) registry.timeAttestationChallenge(tenantId, archiveId);
    return notaryRequests.list(tenantId, { archiveId, ...options });
  }

  function evidenceTimeAttestationRequestStatus(tenantId) {
    return notaryRequests.tenantStatus(tenantId);
  }

  function verifyEvidenceTimeAttestationRequests(tenantId) {
    return notaryRequests.verifyTenant(tenantId);
  }

  function verify(tenantId, evidenceId = null) {
    const base = registry.verify(tenantId, evidenceId);
    return {
      ...base,
      notaryRequests: notaryRequests.enabled
        ? notaryRequests.verifyTenant(tenantId)
        : { valid: true, enabled: false }
    };
  }

  function health() {
    const base = registry.health();
    const delivery = notaryRequests.health();
    const unavailable = notaryRequests.required && delivery.status === 'unavailable';
    const degraded = notaryRequests.required && delivery.status === 'degraded';
    return {
      ...base,
      required: Boolean(base.required || notaryRequests.required),
      status: unavailable || base.status === 'unavailable'
        ? 'unavailable'
        : degraded && base.status === 'ready' ? 'attention' : base.status,
      notaryRequests: delivery
    };
  }

  function tenantStatus(tenantId) {
    const base = registry.tenantStatus(tenantId);
    const delivery = notaryRequests.tenantStatus(tenantId);
    const unavailable = notaryRequests.required && delivery.status === 'unavailable';
    const attention = notaryRequests.required && (delivery.status === 'attention' || delivery.deadLetters > 0);
    return {
      ...base,
      status: unavailable || base.status === 'unavailable'
        ? 'unavailable'
        : attention && base.status === 'ready' ? 'attention' : base.status,
      notaryRequests: delivery
    };
  }

  return Object.freeze({
    ...registry,
    recordTimeAttestation,
    verify,
    health,
    tenantStatus,
    queueTimeAttestationRequest,
    requeueTimeAttestationRequest,
    claimTimeAttestationRequests,
    acknowledgeTimeAttestationRequest,
    failTimeAttestationRequest,
    evidenceTimeAttestationRequests,
    evidenceTimeAttestationRequestStatus,
    verifyEvidenceTimeAttestationRequests,
    evidenceTimeAttestationRequestEnabled: notaryRequests.enabled,
    evidenceTimeAttestationRequestOutbox: notaryRequests
  });
}

export function createEvidenceTimeAttestationRequestRegistryFromEnvironment(env = process.env) {
  const registry = createEvidenceAssuranceBundleRegistryFromEnvironment(env);
  const notaryRequests = createEvidenceTimeAttestationRequestOutboxFromEnvironment({ env });
  if (notaryRequests.enabled && !registry.evidenceTimeAttestationEnabled) {
    throw new TypeError('Evidence-notary request delivery requires enabled time attestations.');
  }
  return createEvidenceTimeAttestationRequestRegistry({ registry, notaryRequests });
}

function identifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{1,191}$/.test(text)) {
    throw new EvidenceValidationError(`${field} is invalid.`, { field });
  }
  return text;
}
function cleanText(value, field, minimum, maximum) {
  const text = String(value ?? '').trim();
  if (text.length < minimum || text.length > maximum) {
    throw new EvidenceValidationError(`${field} must contain ${minimum} to ${maximum} characters.`, { field });
  }
  return text;
}
