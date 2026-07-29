import {
  auditEngagements as seededEngagements,
  auditFindings as seededFindings,
  auditProviders,
  auditUniverse
} from '../data/workforceAuditFixtures.js';

const ALLOWED_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const CLOSED_STATUSES = new Set(['closed', 'verified']);

export class ValidationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ValidationError';
    this.code = 'VALIDATION_ERROR';
    this.details = details;
  }
}

export class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
    this.code = 'NOT_FOUND';
  }
}

export function createWorkforceAuditService({ now = () => new Date() } = {}) {
  const engagements = structuredClone(seededEngagements);
  const findings = structuredClone(seededFindings);

  function getUniverse() {
    return auditUniverse.map((item) => ({
      ...item,
      readinessScore: calculateUniverseReadiness(item),
      reviewOverdue: daysSince(item.lastReviewedAt, now()) > 365
    }));
  }

  function getEngagements() {
    return structuredClone(engagements);
  }

  function getFindings() {
    return structuredClone(findings);
  }

  function getProviders() {
    return auditProviders.map((provider) => assessProviderReadiness(provider, now()));
  }

  function getOverview() {
    const universe = getUniverse();
    const providers = getProviders();
    const readyUniverse = universe.filter((item) => item.readinessScore >= 80).length;
    const readyProviders = providers.filter((provider) => provider.readiness === 'ready').length;
    const expiringPlaceholders = engagements.flatMap((engagement) => engagement.fieldworkPlaceholders ?? [])
      .filter((placeholder) => daysUntil(placeholder.expiresAt, now()) <= 14);

    return {
      generatedAt: now().toISOString(),
      universe: {
        total: universe.length,
        ready: readyUniverse,
        attentionRequired: universe.length - readyUniverse
      },
      engagements: {
        total: engagements.length,
        active: engagements.filter((item) => ['planned', 'fieldwork', 'reporting'].includes(item.status)).length
      },
      findings: {
        total: findings.length,
        criticalOrHigh: findings.filter((item) => ['critical', 'high'].includes(item.severity) && !CLOSED_STATUSES.has(item.status)).length,
        awaitingManagementResponse: findings.filter((item) => item.managementResponseRequired && item.status !== 'closed').length
      },
      providers: {
        total: providers.length,
        ready: readyProviders,
        blocked: providers.length - readyProviders
      },
      fieldworkPlaceholders: {
        expiringWithin14Days: expiringPlaceholders.length
      }
    };
  }

  function createEngagement(input) {
    assertObject(input, 'engagement');
    const required = ['universeItemId', 'objective', 'scope', 'leadAuditor', 'startDate', 'endDate'];
    assertRequired(input, required);

    if (!auditUniverse.some((item) => item.id === input.universeItemId)) {
      throw new ValidationError('The selected audit-universe item does not exist.', { field: 'universeItemId' });
    }
    if (!Array.isArray(input.scope) || input.scope.length === 0 || input.scope.some((item) => typeof item !== 'string' || !item.trim())) {
      throw new ValidationError('Engagement scope must contain at least one non-empty boundary.', { field: 'scope' });
    }
    const startDate = parseDate(input.startDate, 'startDate');
    const endDate = parseDate(input.endDate, 'endDate');
    if (endDate <= startDate) {
      throw new ValidationError('Engagement endDate must be after startDate.', { field: 'endDate' });
    }
    if (input.managementApproved !== true) {
      throw new ValidationError('Management approval is required before an engagement can enter the plan.', {
        field: 'managementApproved'
      });
    }

    const overlap = engagements.find((item) =>
      item.universeItemId === input.universeItemId &&
      new Date(item.startDate) <= endDate &&
      new Date(item.endDate) >= startDate &&
      item.status !== 'cancelled'
    );
    if (overlap) {
      throw new ValidationError('An overlapping engagement already exists for this audit-universe item.', {
        conflictingEngagementId: overlap.id
      });
    }

    const engagement = {
      id: `ENG-${now().getUTCFullYear()}-${String(engagements.length + 5).padStart(3, '0')}`,
      universeItemId: input.universeItemId,
      objective: cleanText(input.objective),
      scope: input.scope.map(cleanText),
      exclusions: Array.isArray(input.exclusions) ? input.exclusions.map(cleanText).filter(Boolean) : [],
      leadAuditor: cleanText(input.leadAuditor),
      startDate: input.startDate,
      endDate: input.endDate,
      managementApproved: true,
      status: 'planned',
      fieldworkPlaceholders: []
    };
    engagements.push(engagement);
    return structuredClone(engagement);
  }

  function addFieldworkPlaceholder(engagementId, input) {
    const engagement = engagements.find((item) => item.id === engagementId);
    if (!engagement) throw new NotFoundError('Audit engagement was not found.');
    assertObject(input, 'fieldwork placeholder');
    assertRequired(input, ['title', 'reason', 'owner', 'expiresAt']);
    const expiresAt = parseDate(input.expiresAt, 'expiresAt');
    if (expiresAt <= now()) {
      throw new ValidationError('A fieldwork placeholder must expire in the future.', { field: 'expiresAt' });
    }
    if (daysUntil(input.expiresAt, now()) > 60) {
      throw new ValidationError('A fieldwork placeholder cannot remain open for more than 60 days.', { field: 'expiresAt' });
    }

    const placeholder = {
      id: `PLH-${engagementId}-${String((engagement.fieldworkPlaceholders?.length ?? 0) + 1).padStart(2, '0')}`,
      title: cleanText(input.title),
      reason: cleanText(input.reason),
      owner: cleanText(input.owner),
      expiresAt: input.expiresAt,
      replacementEvidenceRequired: true,
      status: 'open'
    };
    engagement.fieldworkPlaceholders ??= [];
    engagement.fieldworkPlaceholders.push(placeholder);
    return structuredClone(placeholder);
  }

  function createFinding(input) {
    assertObject(input, 'finding');
    assertRequired(input, ['engagementId', 'title', 'severity', 'owner', 'dueDate', 'evidenceRefs']);
    if (!engagements.some((item) => item.id === input.engagementId)) {
      throw new ValidationError('The selected audit engagement does not exist.', { field: 'engagementId' });
    }
    if (!ALLOWED_SEVERITIES.has(input.severity)) {
      throw new ValidationError('Finding severity must be low, medium, high, or critical.', { field: 'severity' });
    }
    if (!Array.isArray(input.evidenceRefs) || input.evidenceRefs.length === 0) {
      throw new ValidationError('At least one traceable evidence reference is required.', { field: 'evidenceRefs' });
    }
    if (CLOSED_STATUSES.has(input.status) && input.evidenceRefs.some((ref) => String(ref).startsWith('PLH-'))) {
      throw new ValidationError('Placeholder evidence cannot support finding closure.', { field: 'evidenceRefs' });
    }

    const finding = {
      id: `FND-${now().getUTCFullYear()}-${String(findings.length + 12).padStart(3, '0')}`,
      engagementId: input.engagementId,
      title: cleanText(input.title),
      severity: input.severity,
      owner: cleanText(input.owner),
      dueDate: input.dueDate,
      evidenceRefs: input.evidenceRefs.map(cleanText),
      managementResponseRequired: input.managementResponseRequired !== false,
      status: input.status ?? 'draft'
    };
    parseDate(finding.dueDate, 'dueDate');
    findings.push(finding);
    return structuredClone(finding);
  }

  return {
    getOverview,
    getUniverse,
    getEngagements,
    getFindings,
    getProviders,
    createEngagement,
    addFieldworkPlaceholder,
    createFinding
  };
}

export function calculateUniverseReadiness(item) {
  const evidence = clamp(item.evidenceCoverage);
  const controls = clamp(item.controlCoverage);
  const findingPenalty = Math.min(Number(item.openFindings ?? 0) * 4, 20);
  return Math.max(0, Math.round(evidence * 0.45 + controls * 0.55 - findingPenalty));
}

export function assessProviderReadiness(provider, now = new Date()) {
  const blockers = [];
  if (!provider.independenceConfirmed) blockers.push('independence_not_confirmed');
  if (provider.securityReviewStatus !== 'approved') blockers.push('security_review_not_approved');
  if (!provider.dataProcessingAgreement) blockers.push('data_processing_agreement_missing');
  if (provider.capacityStatus !== 'available') blockers.push('delivery_capacity_not_available');
  if (daysSince(provider.lastDueDiligenceAt, now) > 365) blockers.push('due_diligence_expired');
  return { ...provider, readiness: blockers.length ? 'blocked' : 'ready', blockers };
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ValidationError(`A valid ${label} object is required.`);
  }
}

function assertRequired(input, fields) {
  const missing = fields.filter((field) => input[field] === undefined || input[field] === null || input[field] === '');
  if (missing.length) throw new ValidationError('Required fields are missing.', { missing });
}

function cleanText(value) {
  return String(value).trim().replace(/[<>]/g, '');
}

function parseDate(value, field) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new ValidationError(`${field} must be a valid date.`, { field });
  return date;
}

function daysSince(value, now) {
  return Math.floor((now.getTime() - new Date(value).getTime()) / 86_400_000);
}

function daysUntil(value, now) {
  return Math.ceil((new Date(value).getTime() - now.getTime()) / 86_400_000);
}

function clamp(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
}
