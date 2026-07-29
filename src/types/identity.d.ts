import type { AuditRole, AuditPrincipal } from './workforceAudit.d.ts';

export type IdentityEntitlementMode = 'disabled' | 'observe' | 'enforce';
export type IdentityEntitlementStatus = 'active' | 'suspended' | 'unprovisioned' | 'mismatched' | 'review_overdue';

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
