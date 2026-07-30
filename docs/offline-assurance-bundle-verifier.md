# Offline assurance bundle verifier

Pass 23 adds a dependency-free recipient-side verifier for governed evidence assurance bundles. It operates entirely on local files and does not contact BasitClaw, the recipient organisation, a notary authority or any external service.

## Usage

```bash
npm run assurance-bundle:verify -- \
  --package ./claimed-bundle.json \
  --private-key ./recipient-private-key.pem \
  --expected-bundle-id ASB-0123456789abcdef0123456789abcdef \
  --expected-package-sha256 <claim-package-sha256> \
  --expected-recipient-key-id 2026-q3
```

The package file may contain the sealed-package object directly or a claimed-bundle object with `bundleId`, `packageSha256` and `sealedPackage`.

By default, verification fails when the bundle is cryptographically valid but current notary governance marks its proof operationally unacceptable. For forensic inspection only:

```bash
npm run assurance-bundle:verify -- \
  --package ./claimed-bundle.json \
  --private-key ./recipient-private-key.pem \
  --allow-operationally-unacceptable
```

This flag does not make the evidence acceptable. It permits a redacted report so the reviewer can inspect why operational policy failed.

Use `--output ./verification-report.json` to create a new `0600` report file. Existing files are never overwritten.

## Verification sequence

The verifier:

1. enforces the exact sealed-package schema and algorithm `RSA-OAEP-SHA256+A256GCM`;
2. validates the expected claim package digest, bundle ID and recipient public-key ID when supplied;
3. requires an RSA private key of at least 2048 bits;
4. unwraps the AES key using RSA-OAEP SHA-256;
5. authenticates and decrypts the package using AES-256-GCM;
6. validates the plaintext SHA-256 and AAD binding to bundle ID and recipient key;
7. checks package and manifest identities;
8. recalculates the manifest digest and every section digest;
9. decodes evidence bytes and verifies SHA-256, size and immutable-version metadata;
10. requires a valid custody verification result;
11. evaluates the included operational notary-governance posture;
12. reports whether the delivery window has expired.

The report contains identifiers, hashes, counts, posture and timestamps. It never includes evidence bytes, `contentBase64`, the unwrapped content key or private-key material.

## Key handling

Run the verifier on an approved offline or controlled workstation. The CLI reads the PEM private key into process memory, never writes it and zeroes the unwrapped AES key. Operating-system swap, crash dumps, shell history, endpoint security tooling and administrator access remain outside the JavaScript process boundary and must be governed separately.

Do not upload recipient private keys to BasitClaw or include them in package JSON.

## Limits

The verifier demonstrates internal consistency, recipient-key encryption, evidence digest integrity and the governance posture included when the bundle was assembled. It does not independently query later revocations, prove recipient identity, establish legal admissibility or replace legal and professional assurance judgement. Obtain a newer bundle when current policy status matters.
