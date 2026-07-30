export type EvidenceAssuranceGovernanceState =
  | 'pending'
  | 'approved'
  | 'sealed'
  | 'rejected'
  | 'revoked'
  | 'delivered'
  | 'expired';

export interface EvidenceAssuranceGovernanceApproval {
  actor: string;
  role: string;
  approvedAt: string;
}

export interface EvidenceAssuranceGovernanceRequest {
  requestId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  recipientId: string;
  purpose: string;
  purposeCode: string;
  legalBasis: string;
  residencyZone: string;
  requestedBy: string;
  requestedByRole: string;
  requestedAt: string;
  expiresAt: string;
  state: EvidenceAssuranceGovernanceState;
  approvals: EvidenceAssuranceGovernanceApproval[];
  approvalQuorum: number;
  readyToSeal: boolean;
  bundleId: string | null;
  bundlePackageSha256: string | null;
  sealedAt: string | null;
  rejectedAt: string | null;
  revokedAt: string | null;
  deliveredAt: string | null;
  eventCount: number;
  chainHead: string | null;
}

export interface EvidenceAssuranceGovernanceReport {
  total: number;
  approvalQuorum: number;
  byState: Record<EvidenceAssuranceGovernanceState, number>;
  byRecipient: Record<string, number>;
  byPurposeCode: Record<string, number>;
  byResidencyZone: Record<string, number>;
}

export interface EvidenceAssuranceGovernanceHealth {
  status: 'disabled' | 'ready' | 'attention' | 'unavailable';
  enabled: boolean;
  required: boolean;
  mode?: 'encrypted-assurance-approval-governance';
  encryptedRecords?: boolean;
  hashChainedEvents?: boolean;
  bundleIndexEncrypted?: boolean;
  approvalQuorum: number;
  recipientPolicies?: number;
  requestTtlMinutes?: number;
  error?: string;
}
