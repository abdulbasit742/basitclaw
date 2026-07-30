import {
  auditEngagements as seededEngagements,
  auditFindings as seededFindings,
  auditProviders,
  auditUniverse
} from '../data/workforceAuditFixtures.js';
import { PersistenceError } from '../persistence/encryptedSnapshotStore.js';
import {
  createAuditSamplingPlan,
  expectedAuditConclusion,
  verifyAuditSamplingPlan
} from './auditSampling.js';

const ALLOWED_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const CLOSED_STATUSES = new Set(['closed', 'verified']);
const PROGRAMME_STATUSES = new Set(['fieldwork', 'review_pending', 'finalised']);
const STEP_OUTCOMES = new Set(['pass', 'deviation', 'not_applicable']);
const CONCLUSIONS = new Set(['effective', 'effective_with_exceptions', 'inconclusive', 'ineffective']);

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

export function createWorkforceAuditService({
  now = () => new Date(),
  tenantId = 'tenant-demo',
  ledger = null,
  initialState = null,
  persist = null
} = {}) {
  validateTenantId(tenantId);
  let engagements = structuredClone(initialState?.engagements ?? seededEngagements);
  let findings = structuredClone(initialState?.findings ?? seededFindings);
  let testProgrammes = structuredClone(initialState?.testProgrammes ?? []);

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

  function getTestProgrammes({ engagementId = null, status = null } = {}) {
    if (engagementId !== null && !engagements.some((item) => item.id === engagementId)) throw new NotFoundError('Audit engagement was not found.');
    if (status !== null && !PROGRAMME_STATUSES.has(String(status))) throw new ValidationError('Test programme status is invalid.', { field: 'status' });
    return structuredClone(testProgrammes.filter((programme) => (!engagementId || programme.engagementId === engagementId) && (!status || programme.status === status)));
  }

  function getTestProgramme(programmeId) {
    const programme = findProgramme(programmeId);
    return structuredClone(programme);
  }

  function exportState() {
    return {
      engagements: structuredClone(engagements),
      findings: structuredClone(findings),
      testProgrammes: structuredClone(testProgrammes)
    };
  }

  function getOverview() {
    const universe = getUniverse();
    const providers = getProviders();
    const readyUniverse = universe.filter((item) => item.readinessScore >= 80).length;
    const readyProviders = providers.filter((provider) => provider.readiness === 'ready').length;
    const expiringPlaceholders = engagements.flatMap((engagement) => engagement.fieldworkPlaceholders ?? [])
      .filter((placeholder) => daysUntil(placeholder.expiresAt, now()) <= 14);

    return {
      tenantId,
      generatedAt: now().toISOString(),
      universe: { total: universe.length, ready: readyUniverse, attentionRequired: universe.length - readyUniverse },
      engagements: {
        total: engagements.length,
        active: engagements.filter((item) => ['planned', 'fieldwork', 'reporting'].includes(item.status)).length
      },
      testProgrammes: {
        total: testProgrammes.length,
        fieldwork: testProgrammes.filter((item) => item.status === 'fieldwork').length,
        awaitingReview: testProgrammes.filter((item) => item.status === 'review_pending').length,
        finalised: testProgrammes.filter((item) => item.status === 'finalised').length,
        ineffectiveOrInconclusive: testProgrammes.filter((item) => ['ineffective', 'inconclusive'].includes(item.review?.conclusion)).length
      },
      findings: {
        total: findings.length,
        criticalOrHigh: findings.filter((item) => ['critical', 'high'].includes(item.severity) && !CLOSED_STATUSES.has(item.status)).length,
        awaitingManagementResponse: findings.filter((item) => item.managementResponseRequired && item.status !== 'closed').length
      },
      providers: { total: providers.length, ready: readyProviders, blocked: providers.length - readyProviders },
      fieldworkPlaceholders: { expiringWithin14Days: expiringPlaceholders.length }
    };
  }

  function createEngagement(input, context = {}) {
    assertObject(input, 'engagement');
    assertRequired(input, ['universeItemId', 'objective', 'scope', 'leadAuditor', 'startDate', 'endDate']);
    if (!auditUniverse.some((item) => item.id === input.universeItemId)) {
      throw new ValidationError('The selected audit-universe item does not exist.', { field: 'universeItemId' });
    }
    if (!Array.isArray(input.scope) || input.scope.length === 0 || input.scope.some((item) => typeof item !== 'string' || !item.trim())) {
      throw new ValidationError('Engagement scope must contain at least one non-empty boundary.', { field: 'scope' });
    }
    const startDate = parseDate(input.startDate, 'startDate');
    const endDate = parseDate(input.endDate, 'endDate');
    if (endDate <= startDate) throw new ValidationError('Engagement endDate must be after startDate.', { field: 'endDate' });
    if (input.managementApproved !== true) {
      throw new ValidationError('Management approval is required before an engagement can enter the plan.', { field: 'managementApproved' });
    }
    const overlap = engagements.find((item) => item.universeItemId === input.universeItemId && new Date(item.startDate) <= endDate && new Date(item.endDate) >= startDate && item.status !== 'cancelled');
    if (overlap) {
      throw new ValidationError('An overlapping engagement already exists for this audit-universe item.', { conflictingEngagementId: overlap.id });
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

    return commitMutation(() => {
      engagements.push(engagement);
      recordGovernance('engagement.created', 'engagement', engagement.id, context, {
        universeItemId: engagement.universeItemId,
        startDate: engagement.startDate,
        endDate: engagement.endDate
      });
      return structuredClone(engagement);
    });
  }

  function addFieldworkPlaceholder(engagementId, input, context = {}) {
    const engagement = engagements.find((item) => item.id === engagementId);
    if (!engagement) throw new NotFoundError('Audit engagement was not found.');
    assertObject(input, 'fieldwork placeholder');
    assertRequired(input, ['title', 'reason', 'owner', 'expiresAt']);
    const expiresAt = parseDate(input.expiresAt, 'expiresAt');
    if (expiresAt <= now()) throw new ValidationError('A fieldwork placeholder must expire in the future.', { field: 'expiresAt' });
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

    return commitMutation(() => {
      engagement.fieldworkPlaceholders ??= [];
      engagement.fieldworkPlaceholders.push(placeholder);
      recordGovernance('fieldwork.placeholder.created', 'fieldwork_placeholder', placeholder.id, context, {
        engagementId,
        expiresAt: placeholder.expiresAt,
        replacementEvidenceRequired: true
      });
      return structuredClone(placeholder);
    });
  }

  function createFinding(input, context = {}) {
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

    return commitMutation(() => {
      findings.push(finding);
      recordGovernance('finding.created', 'finding', finding.id, context, {
        engagementId: finding.engagementId,
        severity: finding.severity,
        dueDate: finding.dueDate,
        evidenceCount: finding.evidenceRefs.length
      });
      return structuredClone(finding);
    });
  }

  function createTestProgramme(engagementId, input, context = {}) {
    const engagement = engagements.find((item) => item.id === engagementId);
    if (!engagement) throw new NotFoundError('Audit engagement was not found.');
    if (engagement.status === 'cancelled') throw new ValidationError('A cancelled engagement cannot receive a test programme.', { engagementId });
    assertObject(input, 'test programme');
    assertRequired(input, ['objective', 'controlId', 'assertions', 'population', 'samplingMethod', 'sampleSize', 'confidenceLevel', 'tolerableDeviationRate', 'testSteps', 'reviewer']);
    const preparedBy = actorIdentifier(context.actor, 'preparedBy');
    const reviewer = actorIdentifier(input.reviewer, 'reviewer');
    if (reviewer === preparedBy) throw new ValidationError('The test programme reviewer must be independent from the preparer.', { field: 'reviewer' });
    const assertions = stringArray(input.assertions, 'assertions', 1, 20, 1, 200);
    const testSteps = normaliseTestSteps(input.testSteps);
    const programmeId = nextProgrammeId();
    let sampling;
    try {
      sampling = createAuditSamplingPlan({
        tenantId,
        engagementId,
        programmeId,
        population: input.population,
        method: input.samplingMethod,
        sampleSize: input.sampleSize
      });
    } catch (error) {
      throw new ValidationError(error.message, { field: 'population' });
    }
    const confidenceLevel = confidence(input.confidenceLevel);
    const tolerableDeviationRate = deviationRate(input.tolerableDeviationRate, 'tolerableDeviationRate');
    const expectedDeviationRate = input.expectedDeviationRate === undefined
      ? 0
      : deviationRate(input.expectedDeviationRate, 'expectedDeviationRate');
    if (expectedDeviationRate > tolerableDeviationRate) {
      throw new ValidationError('expectedDeviationRate cannot exceed tolerableDeviationRate.', { field: 'expectedDeviationRate' });
    }
    const programme = {
      id: programmeId,
      engagementId,
      objective: boundedText(input.objective, 'objective', 10, 1000),
      controlId: identifier(input.controlId, 'controlId'),
      assertions,
      status: 'fieldwork',
      preparedBy,
      reviewer,
      createdAt: now().toISOString(),
      dueDate: input.dueDate ? parseDate(input.dueDate, 'dueDate').toISOString() : engagement.endDate,
      confidenceLevel,
      tolerableDeviationRate,
      expectedDeviationRate,
      testSteps,
      sampling: {
        version: sampling.version,
        method: sampling.method,
        populationSize: sampling.populationSize,
        sampleSize: sampling.sampleSize,
        populationDigest: sampling.populationDigest,
        seed: sampling.seed,
        manifest: sampling.manifest
      },
      samples: sampling.selected.map((item, index) => ({
        sampleId: `SMP-${programmeId}-${String(index + 1).padStart(4, '0')}`,
        selectionOrder: item.selectionOrder,
        recordId: item.recordId,
        stratum: item.stratum,
        riskScore: item.riskScore,
        attempts: [],
        status: 'pending'
      })),
      submission: null,
      review: null
    };

    return commitMutation(() => {
      testProgrammes.push(programme);
      recordGovernance('test_programme.created', 'test_programme', programme.id, context, {
        engagementId,
        controlId: programme.controlId,
        populationSize: programme.sampling.populationSize,
        sampleSize: programme.sampling.sampleSize,
        samplingMethod: programme.sampling.method,
        populationDigest: programme.sampling.populationDigest,
        reviewer
      });
      return structuredClone(programme);
    });
  }

  function recordTestResult(programmeId, sampleId, input, context = {}) {
    const programme = findProgramme(programmeId);
    if (programme.status !== 'fieldwork') throw new ValidationError('Test results can be recorded only while the programme is in fieldwork.', { programmeId, status: programme.status });
    const sample = programme.samples.find((item) => item.sampleId === sampleId);
    if (!sample) throw new NotFoundError('Audit test sample was not found.');
    const testedBy = actorIdentifier(context.actor, 'testedBy');
    if (testedBy === programme.reviewer) throw new ValidationError('The assigned reviewer cannot execute sample testing.', { reviewer: programme.reviewer });
    assertObject(input, 'sample test result');
    const stepResults = normaliseStepResults(input.stepResults, programme.testSteps);
    const existingAttempts = sample.attempts?.length ?? 0;
    const retestReason = existingAttempts
      ? boundedText(input.retestReason, 'retestReason', 10, 500)
      : null;
    const outcomes = stepResults.map((item) => item.outcome);
    const overallOutcome = outcomes.includes('deviation')
      ? 'deviation'
      : outcomes.every((value) => value === 'not_applicable')
        ? 'not_applicable'
        : 'pass';
    const attempt = {
      attempt: existingAttempts + 1,
      testedBy,
      testedAt: now().toISOString(),
      overallOutcome,
      retestReason,
      stepResults,
      notes: input.notes ? boundedText(input.notes, 'notes', 1, 2000) : null
    };

    return commitMutation(() => {
      sample.attempts ??= [];
      sample.attempts.push(attempt);
      sample.status = 'executed';
      recordGovernance(existingAttempts ? 'test_sample.retested' : 'test_sample.executed', 'test_sample', sample.sampleId, context, {
        programmeId,
        engagementId: programme.engagementId,
        recordId: sample.recordId,
        attempt: attempt.attempt,
        overallOutcome,
        deviationSteps: stepResults.filter((item) => item.outcome === 'deviation').length,
        evidenceCount: stepResults.reduce((sum, item) => sum + item.evidenceRefs.length, 0)
      });
      return structuredClone(sample);
    });
  }

  function submitTestProgramme(programmeId, input, context = {}) {
    const programme = findProgramme(programmeId);
    if (programme.status !== 'fieldwork') throw new ValidationError('Only a fieldwork programme can be submitted for review.', { programmeId, status: programme.status });
    const submittedBy = actorIdentifier(context.actor, 'submittedBy');
    if (submittedBy === programme.reviewer) throw new ValidationError('The assigned reviewer cannot submit the programme they will review.', { reviewer: programme.reviewer });
    assertObject(input, 'test programme submission');
    const incompleteSampleIds = programme.samples.filter((sample) => !(sample.attempts?.length)).map((sample) => sample.sampleId);
    if (incompleteSampleIds.length) throw new ValidationError('Every selected sample must have an executed test result before review.', { incompleteSampleIds });
    const placeholderEvidence = programme.samples.flatMap((sample) => latestAttempt(sample).stepResults)
      .flatMap((step) => step.evidenceRefs)
      .filter((reference) => reference.startsWith('PLH-'));
    if (placeholderEvidence.length) throw new ValidationError('Placeholder evidence cannot support a submitted test programme.', { placeholderEvidence });
    const submission = {
      submittedBy,
      submittedAt: now().toISOString(),
      rationale: boundedText(input.rationale, 'rationale', 20, 2000),
      exceptionsEscalated: Boolean(input.exceptionsEscalated)
    };

    return commitMutation(() => {
      programme.status = 'review_pending';
      programme.submission = submission;
      recordGovernance('test_programme.submitted', 'test_programme', programme.id, context, {
        engagementId: programme.engagementId,
        samples: programme.samples.length,
        deviations: programme.samples.filter((sample) => latestAttempt(sample).overallOutcome === 'deviation').length,
        exceptionsEscalated: submission.exceptionsEscalated
      });
      return structuredClone(programme);
    });
  }

  function reviewTestProgramme(programmeId, input, context = {}) {
    const programme = findProgramme(programmeId);
    if (programme.status !== 'review_pending') throw new ValidationError('Only a submitted test programme can be finalised.', { programmeId, status: programme.status });
    const reviewedBy = actorIdentifier(context.actor, 'reviewedBy');
    if (reviewedBy !== programme.reviewer) throw new ValidationError('Only the assigned independent reviewer can finalise the test programme.', { reviewer: programme.reviewer });
    if (programme.samples.some((sample) => sample.attempts.some((attempt) => attempt.testedBy === reviewedBy))) {
      throw new ValidationError('A reviewer who executed sample testing cannot finalise the programme.', { reviewer: reviewedBy });
    }
    assertObject(input, 'test programme review');
    const eligibleSamples = programme.samples.filter((sample) => latestAttempt(sample).overallOutcome !== 'not_applicable');
    if (!eligibleSamples.length) throw new ValidationError('At least one applicable sample is required for a test conclusion.', { programmeId });
    const deviations = eligibleSamples.filter((sample) => latestAttempt(sample).overallOutcome === 'deviation').length;
    let metrics;
    try {
      metrics = expectedAuditConclusion({
        deviations,
        testedItems: eligibleSamples.length,
        tolerableDeviationRate: programme.tolerableDeviationRate,
        confidenceLevel: programme.confidenceLevel
      });
    } catch (error) {
      throw new ValidationError(error.message);
    }
    const conclusion = String(input.conclusion ?? '');
    if (!CONCLUSIONS.has(conclusion) || conclusion !== metrics.conclusion) {
      throw new ValidationError('The review conclusion must match the statistically derived conclusion.', {
        suppliedConclusion: conclusion || null,
        expectedConclusion: metrics.conclusion,
        metrics
      });
    }
    const confirmation = `FINALISE ${programme.id} ${conclusion.toUpperCase()}`;
    if (input.confirmation !== confirmation) throw new ValidationError(`confirmation must be exactly ${confirmation}.`, { field: 'confirmation' });
    const review = {
      reviewedBy,
      reviewedAt: now().toISOString(),
      conclusion,
      rationale: boundedText(input.rationale, 'rationale', 20, 2000),
      metrics
    };

    return commitMutation(() => {
      programme.status = 'finalised';
      programme.review = review;
      recordGovernance('test_programme.finalised', 'test_programme', programme.id, context, {
        engagementId: programme.engagementId,
        conclusion,
        deviations: metrics.deviations,
        testedItems: metrics.testedItems,
        observedDeviationRate: metrics.observedDeviationRate,
        upperDeviationBound: metrics.upperDeviationBound,
        tolerableDeviationRate: metrics.tolerableDeviationRate,
        confidenceLevel: metrics.confidenceLevel
      });
      return structuredClone(programme);
    });
  }

  function verifyTestProgramme(programmeId) {
    const programme = findProgramme(programmeId);
    let sampling;
    try {
      sampling = verifyAuditSamplingPlan({
        tenantId,
        engagementId: programme.engagementId,
        programmeId: programme.id,
        population: programme.sampling.manifest,
        method: programme.sampling.method,
        sampleSize: programme.sampling.sampleSize,
        selectedRecordIds: programme.samples.map((sample) => sample.recordId)
      });
    } catch (error) {
      return { valid: false, programmeId, reason: 'sampling_rebuild_failed', error: error.message };
    }
    const sampleIdentityValid = programme.samples.every((sample, index) => sample.sampleId === `SMP-${programme.id}-${String(index + 1).padStart(4, '0')}` && sample.selectionOrder === index + 1);
    let reviewValid = true;
    let expectedReview = null;
    if (programme.status === 'finalised') {
      const eligibleSamples = programme.samples.filter((sample) => latestAttempt(sample).overallOutcome !== 'not_applicable');
      if (!eligibleSamples.length) reviewValid = false;
      else {
        expectedReview = expectedAuditConclusion({
          deviations: eligibleSamples.filter((sample) => latestAttempt(sample).overallOutcome === 'deviation').length,
          testedItems: eligibleSamples.length,
          tolerableDeviationRate: programme.tolerableDeviationRate,
          confidenceLevel: programme.confidenceLevel
        });
        reviewValid = programme.review?.conclusion === expectedReview.conclusion
          && JSON.stringify(programme.review?.metrics) === JSON.stringify(expectedReview);
      }
    }
    return {
      valid: sampling.valid
        && sampling.populationDigest === programme.sampling.populationDigest
        && sampling.seed === programme.sampling.seed
        && sampleIdentityValid
        && reviewValid,
      programmeId,
      status: programme.status,
      sampling: {
        valid: sampling.valid,
        populationDigestMatches: sampling.populationDigest === programme.sampling.populationDigest,
        seedMatches: sampling.seed === programme.sampling.seed,
        sampleIdentityValid
      },
      review: { valid: reviewValid, expected: expectedReview, recorded: programme.review?.metrics ?? null }
    };
  }

  function commitMutation(mutator) {
    const previousState = exportState();
    const ledgerCheckpoint = ledger?.checkpoint(tenantId) ?? 0;
    try {
      const result = mutator();
      persist?.(exportState());
      return result;
    } catch (error) {
      engagements = previousState.engagements;
      findings = previousState.findings;
      testProgrammes = previousState.testProgrammes;
      ledger?.rollbackTo(tenantId, ledgerCheckpoint);
      if (error instanceof PersistenceError) throw error;
      if (error?.code === 'PERSISTENCE_UNAVAILABLE') throw error;
      throw error;
    }
  }

  function recordGovernance(action, entityType, entityId, context, metadata) {
    if (!ledger) return null;
    return ledger.append({
      tenantId,
      actor: safeActor(context.actor),
      action,
      entityType,
      entityId,
      metadata
    });
  }

  function findProgramme(programmeId) {
    const id = identifier(programmeId, 'programmeId');
    const programme = testProgrammes.find((item) => item.id === id);
    if (!programme) throw new NotFoundError('Audit test programme was not found.');
    return programme;
  }

  function nextProgrammeId() {
    const year = now().getUTCFullYear();
    const prefix = `TPG-${year}-`;
    const highest = testProgrammes
      .map((item) => item.id)
      .filter((id) => id.startsWith(prefix))
      .map((id) => Number(id.slice(prefix.length)))
      .filter(Number.isSafeInteger)
      .reduce((maximum, value) => Math.max(maximum, value), 0);
    return `${prefix}${String(highest + 1).padStart(4, '0')}`;
  }

  return {
    getOverview,
    getUniverse,
    getEngagements,
    getFindings,
    getProviders,
    getTestProgrammes,
    getTestProgramme,
    exportState,
    createEngagement,
    addFieldworkPlaceholder,
    createFinding,
    createTestProgramme,
    recordTestResult,
    submitTestProgramme,
    reviewTestProgramme,
    verifyTestProgramme
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

function normaliseTestSteps(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 50) throw new ValidationError('testSteps must contain 1 to 50 steps.', { field: 'testSteps' });
  const ids = new Set();
  return value.map((step, index) => {
    assertObject(step, `test step ${index + 1}`);
    const stepId = step.stepId ? identifier(step.stepId, `testSteps[${index}].stepId`) : `STEP-${String(index + 1).padStart(2, '0')}`;
    if (ids.has(stepId)) throw new ValidationError(`Test step ${stepId} is duplicated.`, { field: 'testSteps' });
    ids.add(stepId);
    return {
      stepId,
      title: boundedText(step.title, `testSteps[${index}].title`, 3, 200),
      procedure: boundedText(step.procedure, `testSteps[${index}].procedure`, 10, 2000),
      required: step.required !== false
    };
  });
}

function normaliseStepResults(value, testSteps) {
  if (!Array.isArray(value) || value.length !== testSteps.length) {
    throw new ValidationError('stepResults must contain exactly one result for every test step.', { field: 'stepResults', expected: testSteps.length });
  }
  const byId = new Map();
  for (const [index, result] of value.entries()) {
    assertObject(result, `step result ${index + 1}`);
    const stepId = identifier(result.stepId, `stepResults[${index}].stepId`);
    if (byId.has(stepId)) throw new ValidationError(`Step result ${stepId} is duplicated.`, { field: 'stepResults' });
    const outcome = String(result.outcome ?? '');
    if (!STEP_OUTCOMES.has(outcome)) throw new ValidationError('Step outcome must be pass, deviation, or not_applicable.', { field: `stepResults[${index}].outcome` });
    const evidenceRefs = stringArray(result.evidenceRefs ?? [], `stepResults[${index}].evidenceRefs`, outcome === 'not_applicable' ? 0 : 1, 20, 1, 255);
    const notes = result.notes ? boundedText(result.notes, `stepResults[${index}].notes`, 1, 2000) : null;
    if (outcome === 'not_applicable' && !notes) throw new ValidationError('A not_applicable step requires a rationale in notes.', { field: `stepResults[${index}].notes` });
    byId.set(stepId, { stepId, outcome, evidenceRefs, notes });
  }
  const unknown = [...byId.keys()].filter((stepId) => !testSteps.some((step) => step.stepId === stepId));
  const missing = testSteps.filter((step) => !byId.has(step.stepId)).map((step) => step.stepId);
  if (unknown.length || missing.length) throw new ValidationError('Step results do not match the approved test programme.', { unknown, missing });
  return testSteps.map((step) => {
    const result = byId.get(step.stepId);
    if (step.required && result.outcome === 'not_applicable' && !result.notes) throw new ValidationError(`Required step ${step.stepId} needs an applicability rationale.`);
    return result;
  });
}

function latestAttempt(sample) {
  const attempt = sample.attempts?.at(-1);
  if (!attempt) throw new ValidationError('A selected sample has no executed result.', { sampleId: sample.sampleId });
  return attempt;
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ValidationError(`A valid ${label} object is required.`);
}

function assertRequired(input, fields) {
  const missing = fields.filter((field) => input[field] === undefined || input[field] === null || input[field] === '');
  if (missing.length) throw new ValidationError('Required fields are missing.', { missing });
}

function cleanText(value) {
  return String(value).trim().replace(/[<>]/g, '');
}

function boundedText(value, field, minimum, maximum) {
  const text = cleanText(value);
  if (text.length < minimum || text.length > maximum || /[\u0000-\u001f\u007f]/.test(text)) {
    throw new ValidationError(`${field} must contain ${minimum} to ${maximum} printable characters.`, { field });
  }
  return text;
}

function stringArray(value, field, minimumItems, maximumItems, minimumLength, maximumLength) {
  if (!Array.isArray(value) || value.length < minimumItems || value.length > maximumItems) {
    throw new ValidationError(`${field} must contain ${minimumItems} to ${maximumItems} values.`, { field });
  }
  const result = value.map((item, index) => boundedText(item, `${field}[${index}]`, minimumLength, maximumLength));
  if (new Set(result).size !== result.length) throw new ValidationError(`${field} cannot contain duplicate values.`, { field });
  return result;
}

function actorIdentifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@-]{0,191}$/.test(text)) throw new ValidationError(`${field} must be a safe actor identifier.`, { field });
  return text;
}

function identifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:@/-]{0,191}$/.test(text)) throw new ValidationError(`${field} must be a safe identifier.`, { field });
  return text;
}

function confidence(value) {
  const parsed = Number(value);
  if (![0.9, 0.95, 0.99].includes(parsed)) throw new ValidationError('confidenceLevel must be 0.9, 0.95, or 0.99.', { field: 'confidenceLevel' });
  return parsed;
}

function deviationRate(value, field) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) throw new ValidationError(`${field} must be a number from 0 to 1.`, { field });
  return Number(parsed.toFixed(6));
}

function safeActor(value) {
  const actor = String(value ?? 'system').trim();
  return /^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,191}$/.test(actor) ? actor : 'system';
}

function validateTenantId(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(String(value ?? ''))) throw new TypeError('tenantId must be a safe identifier.');
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
