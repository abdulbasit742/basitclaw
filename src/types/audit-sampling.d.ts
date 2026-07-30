export type AuditSamplingMethod = 'simple_random' | 'systematic' | 'monetary_unit' | 'stratified_random';
export type AuditSamplingPlanStatus = 'draft' | 'approved' | 'cancelled';

export interface AuditPopulationInput {
  sourceReference: string;
  amountMinorUnits?: string;
  stratum?: string;
}

export interface AuditSampleSelectionItem {
  position: number;
  itemHash: string;
  amountMinorUnits: string | null;
  stratum: string | null;
}

export interface AuditSampleSelection {
  method: AuditSamplingMethod;
  sampleSize: number;
  selected: AuditSampleSelectionItem[];
  methodDetails: Record<string, unknown>;
  selectionHash: string;
}

export interface AuditSamplingPlan {
  planId: string;
  engagementId: string;
  objective: string;
  rationale: string;
  evidenceId: string;
  evidenceVersion: number;
  evidenceContentSha256: string;
  method: AuditSamplingMethod;
  requestedSampleSize: number;
  populationRoot: string;
  populationCount: number;
  populationValueMinorUnits: string;
  seedCommitment: string;
  seedReveal: string | null;
  status: AuditSamplingPlanStatus;
  preparedBy: string;
  createdAt: string;
  approvedBy: string | null;
  approvedAt: string | null;
  cancelledBy: string | null;
  cancelledAt: string | null;
  selection: AuditSampleSelection | null;
  sourceReferencesPublic: false;
  evidenceBindingCurrent?: boolean;
}

export interface CreateAuditSamplingPlanRequest {
  engagementId: string;
  objective: string;
  rationale: string;
  evidenceId: string;
  evidenceVersion?: number;
  idempotencyKey: string;
  method: AuditSamplingMethod;
  sampleSize: number;
  strata?: Record<string, number>;
  population: AuditPopulationInput[];
}

export interface AuditSamplingVerification {
  valid: true;
  planId: string;
  status: AuditSamplingPlanStatus;
  populationRoot: string;
  populationCount: number;
  seedCommitment: string;
  selectionValid: boolean | null;
  selectionHash: string | null;
  eventCount: number;
  eventHeadHash: string | null;
  evidenceBindingValid?: true;
}

export interface AuditSamplingStatus {
  status: 'disabled' | 'ready' | 'attention' | 'unavailable';
  enabled: boolean;
  plans?: number;
  drafts?: number;
  approved?: number;
  cancelled?: number;
  staleEvidenceBindings?: number;
  assuranceReady?: boolean;
  sourceReferencesPublic: false;
  deterministicVerification?: true;
  statisticalValidityAsserted?: false;
  error?: string;
}
