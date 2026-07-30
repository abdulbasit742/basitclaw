export type EvidenceTimeAttestationGovernanceEventType =
  | 'attestation_revoked'
  | 'provider_revoked'
  | 'key_revoked'
  | 'attestation_superseded';

export type EvidenceTimeAttestationGovernanceReasonCode =
  | 'authority_compromise'
  | 'key_compromise'
  | 'policy_withdrawn'
  | 'provider_termination'
  | 'administrative_error'
  | 'superseded'
  | 'legal_direction'
  | 'other';

export interface EvidenceTimeAttestationGovernanceEvent {
  eventId: string;
  eventType: EvidenceTimeAttestationGovernanceEventType;
  archiveId: string | null;
  attestationId: string | null;
  providerId: string | null;
  keyId: string | null;
  replacementAttestationId: string | null;
  effectiveAt: string;
  retroactive: boolean;
  reasonCode: EvidenceTimeAttestationGovernanceReasonCode;
  reason: string;
  recordedAt: string;
  recordedBy: string;
  sequence: number;
  previousHash: string | null;
  hash: string;
  signingKeyId: string;
  signature: string;
}

export interface EvidenceTimeAttestationGovernanceDecisionReason {
  eventId: string;
  eventType: EvidenceTimeAttestationGovernanceEventType;
  effectiveAt: string;
  reasonCode: EvidenceTimeAttestationGovernanceReasonCode;
  replacementAttestationId: string | null;
  retroactive: boolean;
}

export interface EvidenceTimeAttestationGovernanceDecision {
  attestationId: string;
  cryptographicallyValid: true;
  operationallyAcceptable: boolean;
  status: 'acceptable' | 'revoked' | 'superseded';
  reasons: EvidenceTimeAttestationGovernanceDecisionReason[];
}

export interface EffectiveEvidenceTimeAttestationVerification {
  valid: true;
  archiveId: string;
  cryptographicallyValid: true;
  quorumSatisfied: boolean;
  governanceEnabled: boolean;
  governanceEvaluatedAt: string;
  governanceEventsConsidered: number;
  operationallyAcceptable: boolean;
  operationalQuorumSatisfied: boolean;
  acceptableAttestations: number;
  acceptableDistinctProviders: number;
  acceptableProviderIds: string[];
  rejectedAttestations: number;
  minimumProviders: number;
  attestationDecisions: Array<Record<string, unknown> & {
    governance: EvidenceTimeAttestationGovernanceDecision;
  }>;
}

export interface EvidenceTimeAttestationGovernanceStatus {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  requiredForDisposition: boolean;
  events?: number;
  headSequence?: number;
  headHash?: string | null;
  attestationRevocations?: number;
  providerRevocations?: number;
  keyRevocations?: number;
  supersessions?: number;
  evaluatedAttestations?: number;
  acceptableAttestations?: number;
  revokedAttestations?: number;
  supersededAttestations?: number;
  totalVersions?: number;
  preservedVersions?: number;
  operationalQuorumVersions?: number;
  missingPreservationCount?: number;
  missingOperationalQuorumCount?: number;
  dispositionReady?: boolean;
  error?: string;
}

export interface EvidenceTimeAttestationGovernanceHealth {
  status: 'disabled' | 'ready' | 'unavailable';
  enabled: boolean;
  requiredForDisposition: boolean;
  mode: 'disabled' | 'shared-file-encrypted-time-attestation-governance';
  encrypted?: boolean;
  signedEvents?: boolean;
  appendOnly?: boolean;
  separatesCryptographicValidity?: boolean;
  maximumEvents?: number;
  tenantDirectoryCount?: number;
  error?: string;
}
