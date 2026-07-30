export interface EvidenceTimeAuthorityKeyPolicy {
  algorithm: 'ed25519' | 'rsa-pss-sha256';
  publicKeyPem: string;
  validFrom?: string;
  validUntil?: string;
  allowedPolicyIds?: string[];
}

export interface EvidenceTimeAuthorityPolicyDecision {
  trusted: boolean;
  reason: null | 'unknown_authority_key' | 'timestamp_invalid'
    | 'key_not_yet_valid' | 'key_expired_at_attestation' | 'policy_not_allowed';
}

export interface EvidenceTimeAuthorityProviderPolicyHealth {
  providerId: string;
  configuredKeys: number;
  activeKeys: number;
}

export interface EvidenceTimeAuthorityPolicyHealth {
  status: 'ready' | 'attention' | 'unavailable';
  minimumProviders: number;
  configuredProviders: number;
  activeProviders: number;
  quorumAvailable: boolean;
  activeKeys: number;
  pendingKeys: number;
  expiredKeys: number;
  expiringKeys: number;
  providers: EvidenceTimeAuthorityProviderPolicyHealth[];
}

export interface EvidenceTimeAuthorityPolicyVerification {
  cryptographicQuorumSatisfied: boolean;
  policyCompliantAttestations: number;
  policyRejectedAttestations: number;
  policyCompliantDistinctProviders: number;
  policyCompliantDistinctKeys: number;
  quorumSatisfied: boolean;
  providerIds: string[];
  policyRejectionReasons: Record<string, number>;
}
