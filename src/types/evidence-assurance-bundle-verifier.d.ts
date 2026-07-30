export interface EvidenceAssuranceBundleVerificationReport {
  valid: true;
  bundleId: string;
  recipientId: string;
  recipientPublicKeyId: string;
  evidenceId: string;
  evidenceVersion: number;
  contentSha256: string;
  sizeBytes: number;
  packageSha256: string;
  plaintextSha256: string;
  manifestDigest: string;
  sectionDigests: Readonly<Record<string, string>>;
  custodyVerified: boolean;
  operationallyAcceptable: boolean;
  notaryGovernanceArchives: number;
  createdAt: string;
  expiresAt: string;
  expired: boolean;
  verifiedAt: string;
  warnings: readonly string[];
}
export interface VerifyEvidenceAssuranceBundleInput {
  sealedPackage: Record<string, unknown>;
  privateKeyPem: string;
  expectedBundleId?: string | null;
  expectedPackageSha256?: string | null;
  expectedRecipientPublicKeyId?: string | null;
  requireOperationallyAcceptable?: boolean;
  now?: () => Date;
}
