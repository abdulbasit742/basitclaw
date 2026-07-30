export type AuditSamplingMethod = 'random' | 'systematic' | 'stratified';
export type AuditStepOutcome = 'pass' | 'deviation' | 'not_applicable';
export type AuditProgrammeStatus = 'fieldwork' | 'review_pending' | 'finalised';
export type AuditConclusion = 'effective' | 'effective_with_exceptions' | 'inconclusive' | 'ineffective';
export type AuditConfidenceLevel = 0.9 | 0.95 | 0.99;

export interface AuditPopulationRecord {
  recordId: string;
  stratum: string | null;
  riskScore: number;
}

export interface AuditSamplingMetadata {
  version: 1;
  method: AuditSamplingMethod;
  populationSize: number;
  sampleSize: number;
  populationDigest: string;
  seed: string;
  manifest: AuditPopulationRecord[];
}

export interface AuditTestStep {
  stepId: string;
  title: string;
  procedure: string;
  required: boolean;
}

export interface AuditStepResult {
  stepId: string;
  outcome: AuditStepOutcome;
  evidenceRefs: string[];
  notes: string | null;
}

export interface AuditTestAttempt {
  attempt: number;
  testedBy: string;
  testedAt: string;
  overallOutcome: AuditStepOutcome;
  retestReason: string | null;
  stepResults: AuditStepResult[];
  notes: string | null;
}

export interface AuditSelectedSample {
  sampleId: string;
  selectionOrder: number;
  recordId: string;
  stratum: string | null;
  riskScore: number;
  status: 'pending' | 'executed';
  attempts: AuditTestAttempt[];
}

export interface AuditConclusionMetrics {
  conclusion: AuditConclusion;
  deviations: number;
  testedItems: number;
  observedDeviationRate: number;
  upperDeviationBound: number;
  tolerableDeviationRate: number;
  confidenceLevel: AuditConfidenceLevel;
}

export interface AuditTestProgramme {
  id: string;
  engagementId: string;
  objective: string;
  controlId: string;
  assertions: string[];
  status: AuditProgrammeStatus;
  preparedBy: string;
  reviewer: string;
  createdAt: string;
  dueDate: string;
  confidenceLevel: AuditConfidenceLevel;
  tolerableDeviationRate: number;
  expectedDeviationRate: number;
  testSteps: AuditTestStep[];
  sampling: AuditSamplingMetadata;
  samples: AuditSelectedSample[];
  submission: null | {
    submittedBy: string;
    submittedAt: string;
    rationale: string;
    exceptionsEscalated: boolean;
  };
  review: null | {
    reviewedBy: string;
    reviewedAt: string;
    conclusion: AuditConclusion;
    rationale: string;
    metrics: AuditConclusionMetrics;
  };
}

export interface AuditTestProgrammeIntegrity {
  valid: boolean;
  programmeId: string;
  status: AuditProgrammeStatus;
  sampling: {
    valid: boolean;
    populationDigestMatches: boolean;
    seedMatches: boolean;
    sampleIdentityValid: boolean;
  };
  review: {
    valid: boolean;
    expected: AuditConclusionMetrics | null;
    recorded: AuditConclusionMetrics | null;
  };
}
