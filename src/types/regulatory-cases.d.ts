export type RegulatoryCaseType = 'regulator_request' | 'external_audit' | 'legal_request' | 'certification_review';
export type RegulatoryCasePriority = 'normal' | 'high' | 'critical';
export type RegulatoryCaseState = 'open' | 'response_pending' | 'response_approved' | 'closed' | 'cancelled';
export type RegulatoryDeadlineState = 'on_track' | 'due_soon' | 'overdue' | 'complete';

export interface RegulatoryEvidenceReference {
  evidenceId: string;
  version: number;
  contentSha256: string;
  sizeBytes: number;
  filename: string;
  mediaType: string;
}

export interface RegulatoryResponse {
  responseReference: string;
  responseSummary: string;
  submittedAt: string;
  submittedBy: string;
  approvedAt: string | null;
  approvedBy: string | null;
  approvalReason: string | null;
}

export interface RegulatoryCase {
  caseId: string;
  type: RegulatoryCaseType;
  priority: RegulatoryCasePriority;
  state: RegulatoryCaseState;
  authority: string;
  jurisdiction: string;
  requestReference: string;
  legalBasis: string;
  summary: string;
  receivedAt: string;
  dueAt: string;
  deadlineState: RegulatoryDeadlineState;
  owner: string;
  evidence: RegulatoryEvidenceReference[];
  createdAt: string;
  createdBy: string;
  response: RegulatoryResponse | null;
  closure: { closedAt: string; closedBy: string; reason: string } | null;
  cancellation: { cancelledAt: string; cancelledBy: string; reason: string } | null;
}

export interface RegulatoryCaseStatus {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  total?: number;
  open?: number;
  responsePending?: number;
  responseApproved?: number;
  closed?: number;
  cancelled?: number;
  overdue?: number;
  dueSoon?: number;
  headSequence?: number;
  headHash?: string | null;
  error?: string;
}

export interface RegulatoryCaseEvent {
  eventId: string;
  sequence: number;
  previousHash: string | null;
  hash: string;
  type: string;
  caseId: string;
  actor: string;
  occurredAt: string;
  details: Record<string, unknown>;
}
