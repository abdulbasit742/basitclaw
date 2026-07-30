export type AssuranceExportApprovalState = 'pending' | 'approved' | 'rejected' | 'cancelled' | 'expired' | 'consumed';
export interface AssuranceExportApprovalEntry { actor: string; approvedAt: string; }
export interface AssuranceExportApprovalRequest {
  requestId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  recipientId: string;
  purpose: string;
  requestedBy: string;
  state: AssuranceExportApprovalState;
  requiredApprovals: number;
  approvals: AssuranceExportApprovalEntry[];
  createdAt: string;
  expiresAt: string;
  rejectedAt: string | null;
  rejectedBy: string | null;
  rejectionReason: string | null;
  cancelledAt: string | null;
  cancelledBy: string | null;
  consumedAt: string | null;
  consumedBy: string | null;
  bundleId: string | null;
}
export interface RequestAssuranceExportInput { version?: number; recipientId: string; purpose: string; confirmation: string; }
export interface MaterializeAssuranceExportInput { approvalRequestId: string; confirmation: string; }
export interface AssuranceExportApprovalStatus { status: 'ready' | 'unavailable' | 'disabled'; enabled: boolean; required: boolean; requiredApprovals: number; total?: number; pending?: number; approved?: number; rejected?: number; cancelled?: number; expired?: number; consumed?: number; }
