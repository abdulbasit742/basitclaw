import type { AuditRole, AuditPrincipal } from './workforceAudit.d.ts';

export type IdentityEntitlementMode = 'disabled' | 'observe' | 'enforce';
export type IdentityEntitlementStatus = 'active' | 'suspended' | 'unprovisioned' | 'mismatched' | 'review_overdue';
export type PrivilegedAccessMode = 'disabled' | 'observe' | 'enforce';
export type PrivilegedAccessRequestStatus = 'pending' | 'active' | 'denied' | 'cancelled' | 'revoked' | 'expired';

export interface IdentityEntitlement {
  id: string;
  subject: string;
  tenantId: string;
  role: AuditRole;
  active: boolean;
  displayName: string | null;
  reviewBy: string;
  source: string;
  createdAt: string;
  updatedAt: string;
  version: number;
}

export interface IdentityEntitlementEvent {
  id: string;
  sequence: number;
  occurredAt: string;
  actor: string;
  action: string;
  subject: string;
  tenantId: string;
  role: AuditRole;
  active: boolean;
  reason: string;
  version: number;
  previousHash: string | null;
  hash: string;
}

export interface IdentityEntitlementHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  reviewStatus?: 'ready' | 'attention' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: IdentityEntitlementMode;
  encrypted?: boolean;
  durable?: boolean;
  distributed?: boolean;
  configuredKeyCount?: number;
  total?: number;
  active?: number;
  suspended?: number;
  overdue?: number;
  dueWithin30Days?: number;
  tenantCount?: number;
  sequence?: number;
  error?: string;
}

export interface FederatedAuditPrincipal extends AuditPrincipal {
  authMethod: 'oidc';
  entitlementStatus: IdentityEntitlementStatus;
  entitlementId?: string;
  entitlementVersion?: number;
  entitlementReviewBy?: string;
  approvedTenantId?: string;
  approvedRole?: AuditRole;
  authenticationContext?: { acr: string | null; amr: string[] };
  privilegedAccess?: {
    status: 'active' | 'observed';
    requestId?: string;
    permission: string;
    permissions?: string[];
    expiresAt?: string;
    breakGlass?: boolean;
    reason?: string;
    enforced?: boolean;
  };
}

export interface PrivilegedAccessApproval {
  subject: string;
  role: AuditRole;
  approvedAt: string;
  comment: string;
}

export interface PrivilegedAccessRequest {
  id: string;
  subject: string;
  tenantId: string;
  requesterRole: AuditRole;
  permissions: string[];
  reason: string;
  ticketRef: string;
  durationMinutes: number;
  status: PrivilegedAccessRequestStatus;
  breakGlass: boolean;
  approvalsRequired: number;
  approvals: PrivilegedAccessApproval[];
  requestedAt: string;
  approvalExpiresAt: string | null;
  activatedAt: string | null;
  expiresAt: string | null;
  closedAt: string | null;
  postReviewBy: string | null;
  postReview: null | { reviewer: string; reviewedAt: string; outcome: 'accepted' | 'concern'; reason: string };
  version: number;
}

export interface PrivilegedAccessHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  reviewStatus?: 'ready' | 'attention' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: PrivilegedAccessMode;
  encrypted?: boolean;
  durable?: boolean;
  distributed?: boolean;
  active?: number;
  pending?: number;
  breakGlassActive?: number;
  overduePostReviews?: number;
  protectedPermissionCount?: number;
  approvalsRequired?: number;
  integrity?: { valid: boolean; retainedEvents: number; headSequence?: number; headHash?: string | null };
  error?: string;
}

export interface ScimCredentialHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  total?: number;
  usable?: number;
  retiring?: number;
  nextExpiryAt?: string | null;
}

export interface ScimUserExtension {
  tenantId: string;
  role: AuditRole;
  reviewBy: string;
  entitlementStatus: 'active' | 'suspended';
}
