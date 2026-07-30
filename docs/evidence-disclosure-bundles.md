# Portable assurance disclosure bundles

Pass 26 adds portable, recipient-encrypted assurance packages for external auditors, regulators and approved independent reviewers. A package contains metadata and cryptographic proofs only. It never contains raw evidence bytes.

## Trust boundary

Before creating a package, BasitClaw:

1. verifies the evidence registry and custody chain;
2. requires a verified write-once preservation receipt for every selected version;
3. verifies independent authority signatures;
4. applies pass-20 revocation, compromise and supersession governance;
5. requires the configured quorum of operationally acceptable distinct authorities;
6. signs the sealed package with an enterprise Ed25519 or RSA-PSS-SHA256 key.

The payload is encrypted with a fresh AES-256-GCM key. That key is wrapped to an approved recipient RSA public key using RSA-OAEP-SHA256. Only the recipient holding the corresponding private key can open the package.

BasitClaw does not store recipient private keys, transmit packages to arbitrary URLs or include raw evidence content. Package delivery remains an authorised enterprise process.

## Package contents

The decrypted payload may include:

- a hashed tenant reference;
- evidence ID and lifecycle status;
- selected immutable version numbers;
- media type, byte length and SHA-256 digest;
- optional filenames, only when explicitly requested;
- screening status and finding codes;
- external scanner provider verdicts and timestamps;
- verified preservation receipts;
- independent time-attestation cryptographic fields;
- operational governance status and reason codes;
- cryptographic and operational quorum results;
- registry verification summaries.

It excludes:

- raw evidence bytes or base64 content;
- scanner matched values or excerpts;
- legal-hold matter identifiers;
- free-text notary compromise or investigation reasons;
- API keys, signing keys or encryption keys;
- filesystem paths, claim tokens or scanner packages.

Every payload declares `rawEvidenceIncluded: false`. The offline verifier rejects a package that does not preserve this policy.

## Governance routes

Audit managers and compliance administrators receive `evidence:disclose`.

```text
GET  /api/workforce-audit/disclosure-bundles/status
POST /api/workforce-audit/evidence/{evidenceId}/disclosure-bundles
GET  /api/workforce-audit/evidence/{evidenceId}/disclosure-bundles
GET  /api/workforce-audit/disclosure-bundles/{bundleId}
POST /api/workforce-audit/disclosure-bundles/{bundleId}/verify
```

Create request:

```json
{
  "recipientId": "external-auditor",
  "idempotencyKey": "audit-2026-q3-payroll-001",
  "purpose": "Independent annual workforce controls audit",
  "expiresAt": "2026-08-30T00:00:00.000Z",
  "versions": [1, 2],
  "includeFilenames": false,
  "confirmation": "CREATE DISCLOSURE EVD-0123456789abcdef0123456789abcdef"
}
```

The confirmation must be exact. The idempotency key is tenant/evidence/recipient scoped and creates a deterministic bundle ID. An exact replay returns the original package. Unknown recipients and conflicting records fail before filesystem writes.

## Effective notary governance

A cryptographically valid authority signature is not automatically operationally acceptable. Pass-20 governance may exclude it because the exact attestation, provider or key was revoked, compromised or superseded.

Disclosure creation therefore uses `operationalQuorumSatisfied`, not the older cryptographic-only quorum. A package cannot be created when the acceptable distinct-authority count is below policy. The encrypted payload preserves each attestation's cryptographic identity and current governance status, but exports reason codes rather than free-text governance reasons.

A later governance event does not mutate an already issued package. Operators must create a fresh package to represent current trust posture. Package expiry limits the normal review window, and recipients must always consider the package creation timestamp and current enterprise revocation information.

## Cryptographic envelope

Public package fields are limited to cryptographic routing and expiry information:

- bundle ID;
- recipient and recipient-key reference;
- enterprise signing-key ID;
- creation and expiry timestamps;
- payload and ciphertext SHA-256 digests;
- wrapped AES key, IV, authentication tag and ciphertext;
- enterprise signature.

The enterprise signature covers algorithms, identifiers, timestamps, digests, wrapped key and AES-GCM parameters. Signature verification occurs before recipient decryption.

Supported enterprise signing algorithms:

- Ed25519;
- RSA-PSS-SHA256 with a 32-byte salt and at least 2048-bit RSA keys.

Recipient encryption requires RSA keys of at least 2048 bits.

## Storage

The disclosure directory uses tenant-hashed subdirectories. Each bundle has:

- a create-only sealed `.bundle` package;
- a separately AES-256-GCM encrypted `.record` management file.

The management record binds tenant, evidence, recipient, idempotency key, manifest digest, ciphertext digest, timestamps and actor. Verification checks that the public package matches the encrypted management record. No deletion endpoint exists. Orphan package/record mismatches make tenant disclosure health unavailable.

## Offline verification

The recipient needs:

1. the downloaded `.basitclaw-disclosure.json` package;
2. its RSA private key PEM;
3. an enterprise public-key trust JSON file.

Trust JSON example:

```json
{
  "2026-q3": "/secure/trust/basitclaw-disclosure-2026-q3-public.pem"
}
```

Run:

```bash
npm run disclosure:verify -- \
  ./DSC-example.basitclaw-disclosure.json \
  /secure/recipient/private-key.pem \
  /secure/trust/enterprise-public-keys.json
```

The offline verifier checks the enterprise signature, package digest, expiry, RSA key unwrap, AES-GCM authentication, payload digest, manifest digest and metadata-only policy. It prints a summary by default. Add `--show-payload` to display the decrypted proof payload. Add `--allow-expired` only for an approved historical review.

## Key rotation

### Recipient keys

1. Add the new RSA public key under a new ID.
2. Set the recipient `primaryKeyId` to the new key.
3. Create and offline-verify a test bundle.
4. Retain old recipient private keys while old packages remain reviewable.

### Enterprise signing keys

1. Add a new Ed25519 or RSA private key through the approved secret manager or HSM integration.
2. Change `WORKFORCE_AUDIT_DISCLOSURE_SIGNING_PRIMARY_KEY_ID`.
3. Distribute the public key through the approved trust channel.
4. Retain old public keys for every unexpired or legally retained package.

### Index encryption keys

Add a new AES-256 key and change the primary ID. Historical management records remain readable while old keys remain in the keyring.

## Operational checks

Monitor:

- disclosure store health and orphan counts;
- signing and recipient key age;
- package expiry volume;
- failed offline verification reports;
- idempotency conflicts and unknown-recipient attempts;
- unexpected filename inclusion;
- notary governance changes after bundle creation;
- recipient-key revocation and trust distribution;
- storage capacity and create-only write failures.

A valid BasitClaw package proves that the configured enterprise key signed a recipient-encrypted metadata/proof snapshot. It does not by itself determine legal admissibility, recipient authority, audit sufficiency or regulatory acceptance. Those remain governance and legal decisions.
