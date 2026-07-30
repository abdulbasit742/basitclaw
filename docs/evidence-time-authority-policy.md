# Evidence time-authority key policy

Pass 28 adds static admission policy for the authority public keys used by independent evidence time attestations. It complements—not replaces—the append-only revocation and supersession journal introduced in pass 20.

## Separate responsibilities

Authority key policy controls:

- when a key is authorised to issue attestations (`validFrom` and `validUntil`);
- which authority `policyId` values are accepted (`allowedPolicyIds`);
- expiry warnings and whether active providers can currently satisfy quorum.

The pass-20 governance journal remains the only runtime mechanism for:

- provider or key revocation;
- prospective or retroactive compromise decisions;
- exact-attestation revocation;
- attestation supersession.

Do not model compromise or revocation by silently changing validity dates. Record the governed event so the decision remains encrypted, signed, append-only and reviewable.

## Provider configuration

```json
{
  "qualified-tsa-a": {
    "keys": {
      "2026-q3": {
        "algorithm": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
        "validFrom": "2026-07-01T00:00:00.000Z",
        "validUntil": "2026-10-01T00:00:00.000Z",
        "allowedPolicyIds": ["qualified-time-policy-v1"]
      }
    }
  }
}
```

For a new callback BasitClaw first verifies the asymmetric signature, then applies the configured key window and policy allowlist, and only then sends the record to the existing challenge, timestamp-delay, replay and encrypted-storage controls.

Rejected submissions return `401 EVIDENCE_TIME_AUTHORITY_POLICY_NOT_TRUSTED` with a bounded reason:

- `key_not_yet_valid`;
- `key_expired_at_attestation`;
- `policy_not_allowed`;
- `unknown_authority_key`;
- `signature_encoding` or `signature_invalid`.

## Historical verification

Historical attestations are never deleted or rewritten when policy changes. Verification reports separately:

- `cryptographicQuorumSatisfied` — signatures and the original pass-19 chain verify;
- `quorumSatisfied` — enough distinct providers also comply with the current key-window and policy-ID configuration;
- `policyRejectionReasons` — bounded counts explaining exclusions.

The pass-20 operational quorum then requires both:

1. `authorityPolicy.trusted !== false`; and
2. an operationally acceptable governance decision.

An append-only governance decision cannot restore an expired or disallowed key, and a static key policy cannot override a recorded revocation or supersession.

## Expiry and capacity health

Configure:

```bash
WORKFORCE_AUDIT_EVIDENCE_NOTARY_KEY_EXPIRY_WARNING_DAYS=30
WORKFORCE_AUDIT_EVIDENCE_NOTARY_MAX_ATTESTATIONS_PER_ARCHIVE=5000
```

Health reports active, pending, expiring and expired keys plus active distinct providers. Required notary mode fails closed when active providers cannot satisfy `WORKFORCE_AUDIT_EVIDENCE_NOTARY_MINIMUM_PROVIDERS`. Optional mode reports `attention` rather than false readiness.

Per-archive policy evaluation is bounded. If the cryptographically verified archive contains more records than the configured limit, evaluation fails closed with `EVIDENCE_TIME_AUTHORITY_POLICY_EVALUATION_FAILED`; records are never silently skipped.

## Planned rotation

1. Add the new public key with a new key ID and suitable `validFrom`.
2. Keep the old key configured for historical verification.
3. Confirm enough providers have active keys to maintain quorum.
4. Ask the authority to begin signing with the new key.
5. Verify new attestations and operational quorum.
6. Let the old key pass its `validUntil`; do not delete it while retained records depend on it.

Use the pass-20 governance workflow for early retirement, compromise, provider termination or policy withdrawal.

## Trust boundary

A successful key-policy decision proves only that the signature matches a configured public key and the submitted timestamp/policy falls inside local approved rules. It does not establish provider qualification, RFC 3161 compliance, legal admissibility, jurisdictional status or contractual standing.
