export type ApiCredentialStatus = 'active' | 'retiring' | 'revoked';
export type RateLimitPolicyName = 'burst' | 'authFailure' | 'read' | 'write' | 'sensitive';
export type SecurityEventSeverity = 'info' | 'warning' | 'high' | 'critical';

export interface HashedApiCredentialRecord {
  keyId: string;
  salt: string;
  secretHash: string;
  subject: string;
  tenantId: string;
  role: 'audit_viewer' | 'auditor' | 'audit_manager' | 'compliance_admin';
  status?: ApiCredentialStatus;
  notBefore?: string;
  expiresAt?: string;
}

export interface CredentialHealth {
  status: 'ready' | 'unavailable';
  generatedAt: string;
  total: number;
  usable: number;
  active: number;
  retiring: number;
  revoked: number;
  expired: number;
  notYetActive: number;
  legacyPlaintext: number;
  rotationRequired: number;
  rotationWarningDays: number;
  nextExpiryAt: string | null;
}

export interface RateLimitPolicy {
  limit: number;
  windowMs: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  policy: RateLimitPolicyName;
  limit: number | null;
  remaining: number | null;
  resetAt: string;
  retryAfterSeconds: number;
}

export interface RateLimitHealth {
  status: 'ready' | 'disabled';
  enabled: boolean;
  mode: 'local-memory-fixed-window' | 'disabled';
  distributed: false;
  trustProxyHops: number;
  activeBuckets: number;
  policies: Record<RateLimitPolicyName, RateLimitPolicy>;
}

export interface SecurityEvent {
  id: string;
  sequence: number;
  occurredAt: string;
  type: string;
  severity: SecurityEventSeverity;
  outcome: string;
  requestId: string | null;
  ipFingerprint: string;
  keyId: string | null;
  subject: string | null;
  tenantId: string | null;
  method: string | null;
  route: string | null;
  details: Record<string, unknown>;
  previousHash: string | null;
  hash: string;
}

export interface SecurityTelemetrySummary {
  status: 'ready';
  mode: 'bounded-memory-hash-chain';
  durable: false;
  ephemeralPepper: boolean;
  retainedEvents: number;
  maxEvents: number;
  lastEventAt: string | null;
  countsByType: Record<string, number>;
  countsBySeverity: Record<string, number>;
  integrity: {
    valid: boolean;
    retainedEvents: number;
    failedEventId: string | null;
    headHash: string | null;
  };
}

export interface ApiSecurityStatus {
  credentials: CredentialHealth;
  rateLimiting: RateLimitHealth;
  telemetry: SecurityTelemetrySummary;
}
