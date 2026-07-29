export type ApiCredentialStatus = 'active' | 'retiring' | 'revoked';
export type AuthenticationMode = 'api-key' | 'oidc' | 'hybrid';
export type RateLimitPolicyName = 'burst' | 'authFailure' | 'read' | 'write' | 'sensitive';
export type SecurityEventSeverity = 'info' | 'warning' | 'high' | 'critical';
export type SecurityAlertDeliveryState = 'pending' | 'inflight' | 'delivered' | 'dead-letter';
export type SecurityKeyLifecycleStatus = 'ready' | 'legacy-single-key' | 'unavailable' | 'disabled';

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

export interface ApiKeyCredentialHealth {
  status: 'ready' | 'unavailable' | 'disabled';
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

export interface OidcHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  mode: 'oidc-jwks-bearer' | 'disabled';
  issuerOrigin?: string;
  audienceCount?: number;
  allowedAlgorithms?: Array<'RS256' | 'ES256'>;
  cachedKeys?: number;
  cacheState?: 'cold' | 'fresh' | 'stale' | 'static' | 'disabled';
  fetchedAt?: string | null;
  expiresAt?: string | null;
  staleUntil?: string | null;
  allowedTenants?: number;
  mappedGroups?: number;
  requiredAcrCount?: number;
  requiredAmrCount?: number;
  lastError?: string | null;
}

export interface CredentialHealth extends ApiKeyCredentialHealth {
  authenticationMode?: AuthenticationMode;
  apiKeys?: ApiKeyCredentialHealth;
  oidc?: OidcHealth;
}

export interface RateLimitPolicy { limit: number; windowMs: number; }

export interface RateLimitDecision {
  allowed: boolean;
  policy: RateLimitPolicyName;
  limit: number | null;
  remaining: number | null;
  resetAt: string;
  retryAfterSeconds: number;
  distributed: boolean;
}

export interface RateLimitHealth {
  status: 'ready' | 'degraded' | 'unavailable' | 'disabled';
  enabled: boolean;
  mode: 'local-memory-fixed-window' | 'shared-file-fixed-window' | 'disabled';
  distributed: boolean;
  required: boolean;
  trustProxyHops: number;
  activeBuckets: number | null;
  maxBuckets?: number;
  directory?: string;
  policies: Record<RateLimitPolicyName, RateLimitPolicy>;
  error?: string | null;
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

export interface SecurityArchiveManifest {
  archiveId: string;
  sequence: number;
  writtenAt: string;
  sourceEventId: string | null;
  segment: string;
  hash: string;
  previousHash: string | null;
  keyId: string;
}

export interface ArchivedSecurityEvent extends SecurityEvent { archive: SecurityArchiveManifest; }

export interface SecurityArchiveIntegrity {
  valid: boolean;
  anchorSequence?: number;
  retainedEvents?: number;
  headSequence?: number;
  headHash?: string | null;
  failedArchiveId?: string | null;
  error?: string;
  disabled?: boolean;
}

export interface SecurityArchiveHealth {
  status: 'ready' | 'unavailable' | 'disabled';
  archiveOnlyStatus?: 'ready' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: 'shared-file-encrypted-hash-chain' | 'disabled';
  durable: boolean;
  distributed: boolean;
  encrypted: boolean;
  directory?: string;
  keyId?: string;
  retentionDays?: number;
  maxSegmentBytes?: number;
  retainedSegments?: number;
  anchorSequence?: number;
  headSequence?: number;
  lastArchivedAt?: string | null;
  integrity?: SecurityArchiveIntegrity;
  error?: string | null;
  failures?: number;
  lastError?: string | null;
}

export interface SecurityArchiveExport {
  events: ArchivedSecurityEvent[];
  anchorSequence: number;
  headSequence: number;
  nextSequence: number;
}

export interface SecurityAlertOutboxHealth {
  status: 'ready' | 'degraded' | 'unavailable';
  mode: 'shared-file-durable-outbox';
  durable: true;
  distributed: true;
  directory?: string;
  pending: number;
  inflight: number;
  deadLetters: number;
  oldestPendingAt: string | null;
  error?: string;
}

export interface SecurityAlertDeliveryHealth {
  status: 'ready' | 'degraded' | 'unavailable' | 'disabled';
  enabled: boolean;
  required: boolean;
  mode: 'signed-webhook-durable-outbox' | 'disabled';
  endpointOrigin?: string;
  minimumSeverity?: SecurityEventSeverity;
  includedTypes?: string[];
  maxAttempts?: number;
  timeoutMs?: number;
  pollIntervalMs?: number;
  running?: boolean;
  schedulerStarted?: boolean;
  delivered?: number;
  failed?: number;
  lastCycleAt?: string | null;
  lastSuccessAt?: string | null;
  lastError?: string | null;
  outbox?: SecurityAlertOutboxHealth;
  enqueueFailures?: number;
  lastEnqueueError?: string | null;
}

export interface SecurityAlertDeadLetter {
  version: 1;
  deliveryId: string;
  state: 'dead-letter';
  createdAt: string;
  updatedAt: string;
  deadLetteredAt: string;
  attempts: number;
  lastAttemptAt: string;
  lastStatus: number | null;
  lastError: string | null;
  deadLetterReason: string;
  event: SecurityEvent;
}

export interface SecurityKeyLifecycleSummary {
  status: SecurityKeyLifecycleStatus;
  mode: 'keyring' | 'single-key' | 'disabled' | 'unknown';
  configuredKeyCount: number;
  retainedHistoricalKeyCount: number;
  retirementSafeKeyCount: number;
  missingKeyCount: number;
  rotationReady: boolean;
  receiverOverlapRequired: boolean;
  error: string | null;
}

export interface SecurityTelemetrySummary {
  status: 'ready' | 'unavailable';
  mode: 'bounded-memory-hash-chain' | 'bounded-memory-plus-encrypted-archive';
  durable: boolean;
  distributed: boolean;
  ephemeralPepper: boolean;
  retainedEvents: number;
  maxEvents: number;
  lastEventAt: string | null;
  countsByType: Record<string, number>;
  countsBySeverity: Record<string, number>;
  integrity: { valid: boolean; retainedEvents: number; failedEventId: string | null; headHash: string | null; };
  archive: SecurityArchiveHealth;
  alertDelivery: SecurityAlertDeliveryHealth;
  keyLifecycle: {
    archive: SecurityKeyLifecycleSummary;
    alertSigning: SecurityKeyLifecycleSummary;
  };
}

export interface ApiSecurityStatus {
  credentials: CredentialHealth;
  rateLimiting: RateLimitHealth;
  telemetry: SecurityTelemetrySummary;
}
