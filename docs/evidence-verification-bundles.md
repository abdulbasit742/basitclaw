# Portable evidence verification bundles

Pass 21 adds signed, selectively disclosed proof packages for regulators, external auditors and independent assurance reviewers. A bundle proves that BasitClaw verified an immutable evidence version, its preservation receipt and its currently operational notary quorum at export time.

A portable verification bundle never contains raw evidence bytes, scanner packages, claim tokens, private keys, API keys or matched DLP values. It is a proof package, not an evidence-content disclosure package.

## Trust boundary

BasitClaw signs each bundle with a dedicated Ed25519 or RSA-PSS-SHA256 key. The verifier checks:

- the bundle format and identity;
- the evidence ID, immutable version and content SHA-256;
- the proof digest;
- the preservation archive ID, receipt and encrypted-object digest;
- the operationally acceptable time-attestation quorum summary;
- the accepted time-attestation hash-chain records;
- the bundle expiry;
- the configured export-signing public-key fingerprint;
- the asymmetric bundle signature.

The bundle signer attests that the live BasitClaw registry verified the preservation receipt and applied pass-20 revocation and supersession governance when the export was generated. A historically valid signature that has become operationally revoked, compromised or superseded does not count toward the exported provider quorum and is not included in the accepted-record list.

Privacy-minimised time-attestation records do not include the authorities' raw signatures. Independent authority-signature revalidation therefore still requires the original notary records and trusted authority keys under the pass-19 procedure. Pass-20 governance journals remain the source of truth for why an authority record was excluded.

## Stateless export

The export service is stateless. It does not retain plaintext bundle copies or create another server-side evidence repository. Security telemetry records only privacy-minimised identifiers and outcomes.

Once a recipient receives a bundle, BasitClaw cannot revoke copies already delivered. Use a short expiry, approved transfer channel and a recipient-specific reference. Expiry does not erase a recipient copy; it only makes normal verification fail unless an authorised examiner explicitly uses the expired-bundle review option.

## Production configuration

Use `config/evidence-verification-bundles.production.env.example` as a fail-closed overlay. Production deployments should also enable the pass-20 governance journal and require operational quorum for disposition.

```bash
WORKFORCE_AUDIT_EVIDENCE_BUNDLE_MODE=signed
WORKFORCE_AUDIT_EVIDENCE_BUNDLE_REQUIRE_TIME_QUORUM=true
WORKFORCE_AUDIT_EVIDENCE_BUNDLE_MAX_AGE_DAYS=30
WORKFORCE_AUDIT_EVIDENCE_BUNDLE_PRIMARY_SIGNING_KEY_ID=2026-q3
WORKFORCE_AUDIT_EVIDENCE_BUNDLE_SIGNING_KEYS='{"2026-q3":{"algorithm":"ed25519","privateKeyPem":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"}}'
```

Do not reuse evidence-custody, preservation, notary, governance, TLS, OIDC or JWT keys. Retain old public keys for as long as delivered bundles may need verification. Private keys should remain in the approved secret manager or signing-service boundary.

For production, include `evidence:preserve` in `WORKFORCE_AUDIT_PRIVILEGED_ACCESS_PROTECTED_PERMISSIONS`. That makes proof export require the existing dual-approved, short-lived JIT grant and MFA step-up.

## Export API

Audit managers and compliance administrators already hold the governed `evidence:preserve` permission.

```text
GET  /api/workforce-audit/evidence-verification-bundles/status
POST /api/workforce-audit/evidence/{evidenceId}/verification-bundles
POST /api/workforce-audit/evidence-verification-bundles/verify
```

Example request:

```json
{
  "version": 1,
  "profile": "audit",
  "recipientRef": "external-auditor-2026",
  "purpose": "Independent year-end assurance review",
  "confirmation": "EXPORT PROOF EVD-0123456789abcdef0123456789abcdef V1"
}
```

The confirmation must be exactly `EXPORT PROOF EVD-... V<version>`. The response is a JSON attachment named after the `EVB-...` bundle ID.

Export fails when preservation is missing, cryptographic verification fails, or the pass-20 operational quorum is below the configured number of distinct providers after applying every effective revocation and supersession event.

## Profiles

`minimal` includes the immutable evidence digest, size, media type, retention posture, preservation receipt proof and operational time-attestation quorum.

`audit` adds non-content context such as filename, version count, legal-hold posture and a digest of the verified preservation receipt. Neither profile includes evidence content.

## Offline verification

Save the `bundle` object and the public keyring returned by the status endpoint. Verify without connecting to BasitClaw:

```bash
npm run evidence:bundle:verify -- bundle.json trusted-public-keys.json
```

The trusted keyring format is:

```json
{
  "2026-q3": {
    "algorithm": "ed25519",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "publicKeySha256": "<sha256-of-spki-der>"
  }
}
```

A verifier must obtain this keyring through an authenticated enterprise trust channel. Do not trust a public key embedded only beside the bundle it is meant to verify.

Offline verification proves the bundle signature and internal proof digest. It does not recalculate later notary-governance changes. For a current trust decision, compare the bundle’s generation time and provider set with the authoritative pass-20 governance journal.

## Key rotation

1. Add the new private signing key under a new ID.
2. Distribute its public key and fingerprint through the approved trust channel.
3. Change the primary signing key ID.
4. Export and verify a test bundle.
5. Retain prior public keys while any delivered bundle may require verification.
6. Retire a private key only after the approved signing and incident-response process permits it.

## Incident response

Treat an unexpected export as a potential data-governance incident even though no raw evidence bytes are included. Review the JIT grant, actor, recipient reference, purpose, bundle ID and transfer channel. Rotate the export-signing key if private-key compromise is suspected, distribute a trusted-key revocation notice, and preserve the related security telemetry.

When a notary provider or key is later revoked, do not alter an already delivered bundle. Record the authoritative pass-20 governance event, identify affected bundle recipients, communicate the changed trust posture, and obtain a replacement bundle after operational quorum is restored.
