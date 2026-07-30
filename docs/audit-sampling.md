# Governed reproducible audit sampling

Pass 26 adds encrypted, reproducible workforce-audit sampling plans that are bound to registered evidence populations.

## Assurance boundary

BasitClaw can prove that a specific encrypted population manifest, committed seed and sampling method produced the approved item hashes. It does not prove that:

- the source population is complete;
- the selected audit objective is appropriate;
- the sample size provides a particular confidence level;
- expected deviation, tolerable deviation, materiality or stratification assumptions are correct;
- monetary-unit sampling is suitable for the tested assertion;
- the resulting audit evidence is legally or professionally sufficient.

Those remain auditor judgements and must be documented in the plan rationale and workpapers.

## Privacy and evidence binding

Each plan is bound to:

- tenant;
- engagement;
- registered evidence ID and immutable version;
- evidence-content SHA-256;
- population count and value total;
- canonical population Merkle-like root digest;
- method and requested sample size;
- seed commitment.

Raw `sourceReference` values are stored only inside the AES-256-GCM encrypted plan. Public APIs expose SHA-256 item references. Amounts use decimal integer minor units rather than floating-point currency values.

Approval and verification revalidate the registered evidence version and digest. Disposed, rejected, quarantined or digest-mismatched evidence cannot support approval.

## Methods

### Simple random without replacement

A deterministic HMAC-SHA256 stream drives a Fisher–Yates shuffle. Rejection sampling avoids modulo bias.

### Systematic random-start

The engine derives a random start fraction and a fixed population interval. The ordered population is the canonical item-hash order.

### Monetary-unit sampling

The engine uses positive integer minor units, a deterministic random start and systematic selection points. One item can contain multiple monetary units, so the result records both requested selection points and unique selected items.

### Stratified random

Every population item must have a stratum. The plan can provide exact allocations whose sum equals the sample size, or BasitClaw allocates proportionally using deterministic largest remainders.

## Maker–checker workflow

1. An auditor with `fieldwork:write` prepares a draft.
2. BasitClaw generates a 256-bit seed and publishes only its SHA-256 commitment.
3. A different manager or compliance administrator with `engagement:write` approves using exact confirmation.
4. Approval reveals the seed, executes the immutable method and stores the selection hash.
5. Approved plans cannot be edited or cancelled. A changed scope requires a new plan and idempotency key.

Exact confirmations:

```text
APPROVE SAMPLE SMP-...
CANCEL SAMPLE SMP-...
```

Only unapproved drafts can be cancelled.

## Routes

```text
GET  /api/workforce-audit/sampling-plans/status
GET  /api/workforce-audit/sampling-plans
POST /api/workforce-audit/sampling-plans
GET  /api/workforce-audit/sampling-plans/{planId}
POST /api/workforce-audit/sampling-plans/{planId}/approve
POST /api/workforce-audit/sampling-plans/{planId}/cancel
POST /api/workforce-audit/sampling-plans/{planId}/verify
```

Create request example:

```json
{
  "engagementId": "ENG-2026-payroll",
  "objective": "Test payroll completeness and authorised compensation changes",
  "rationale": "Select a reproducible sample across the complete registered payroll population.",
  "evidenceId": "EVD-0123456789abcdef0123456789abcdef",
  "evidenceVersion": 1,
  "idempotencyKey": "payroll-sample-2026-001",
  "method": "stratified_random",
  "sampleSize": 20,
  "strata": { "hourly": 12, "salaried": 8 },
  "population": [
    { "sourceReference": "payroll-row-0001", "amountMinorUnits": "125000", "stratum": "hourly" }
  ]
}
```

Do not place names, national identifiers, bank details or other unnecessary PII in `sourceReference`. Use a stable internal row key or pseudonymous reference.

## Reproduction

Verification:

1. decrypts and authenticates the plan;
2. canonicalises population entries by item hash;
3. recomputes population root, count and value total;
4. verifies the hash-linked event chain;
5. recomputes the approved selection from the revealed seed;
6. compares item hashes and selection hash;
7. revalidates the source evidence version and SHA-256.

The seed reveal is available only after approval. Event responses never repeat the seed.

## Configuration

```bash
WORKFORCE_AUDIT_SAMPLING_MODE=shared-file
WORKFORCE_AUDIT_SAMPLING_DIR=/var/lib/basitclaw/workforce-audit-sampling
WORKFORCE_AUDIT_SAMPLING_KEYS='{"2026-q3":"<dedicated-base64-32-byte-key>"}'
WORKFORCE_AUDIT_SAMPLING_PRIMARY_KEY_ID=2026-q3
WORKFORCE_AUDIT_SAMPLING_MAX_POPULATION_ITEMS=100000
WORKFORCE_AUDIT_SAMPLING_MAX_PLANS_PER_TENANT=10000
```

Use a dedicated sampling keyring. Retain historical keys while encrypted plans remain in scope.

## Operational checks

Monitor:

- stale evidence bindings;
- draft plans awaiting review;
- failed reproduction checks;
- population and plan limits;
- preparer/approver conflicts;
- unexpected cancellations;
- storage availability and key age;
- whether documented sample-size assumptions remain appropriate after scope changes.
