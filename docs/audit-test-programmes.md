# Governed audit test programmes and sampling

Pass 23 adds a durable audit-methodology workflow for engagement-level control testing. It freezes the declared population, selects a reproducible sample, records evidence-linked execution, separates preparation from review, and prevents a reviewer from choosing a conclusion that conflicts with the recorded deviations and approved tolerance.

## Assurance boundary

The feature provides:

- immutable population manifests inside the encrypted tenant snapshot;
- deterministic `random`, `systematic`, and `stratified` selection;
- SHA-256 population digests and reproducible sampling seeds;
- selected-record identity and order verification;
- approved test steps with one result per selected sample;
- append-only retest attempts with mandatory retest reasons;
- evidence references on every applicable step;
- placeholder-evidence refusal before submission;
- assigned preparer/reviewer separation;
- reviewer exclusion from sample execution;
- one-sided Wilson deviation bounds at 90%, 95%, or 99% confidence;
- governance events for creation, execution, retesting, submission, and finalisation;
- encrypted snapshot, backup, replica, fencing, and recovery coverage through the existing audit registry.

The feature does not prove that the supplied population is complete, authoritative, or free from upstream manipulation. Population completeness remains an audit procedure and should be supported by independent evidence. Statistical results do not replace professional judgement, materiality assessment, fraud-risk evaluation, or applicable audit standards.

## Sampling methods

### Random

Records are sorted by a SHA-256 score derived from the programme seed and stable record ID. The lowest scores are selected. Input-array order does not affect the result.

### Systematic

Records are sorted by stable record ID. A deterministic start position is derived from the programme seed, followed by a fixed population-to-sample interval.

### Stratified

Every population record must have a stratum. When sample size permits, each stratum receives at least one item. Remaining items are allocated proportionally using deterministic largest-deficit allocation, then selected within each stratum by SHA-256 score.

## Population manifest

Each population record contains only:

```json
{
  "recordId": "PAY-0001",
  "stratum": "staff",
  "riskScore": 15
}
```

The full manifest is stored in the encrypted audit snapshot. Record IDs must be unique safe identifiers. `riskScore` is descriptive metadata from 0 to 100; it does not alter the current random, systematic, or proportional stratified selection probability.

The service stores:

- `populationDigest` — SHA-256 of the canonical sorted manifest;
- `seed` — SHA-256 of the tenant, engagement, programme, method, sample size, and population digest;
- selected record IDs and selection order.

`GET /api/workforce-audit/test-programmes/{programmeId}/verify` rebuilds the sample and verifies the digest, seed, selected order, sample identifiers, and final conclusion metrics.

## Create a programme

```text
POST /api/workforce-audit/engagements/{engagementId}/test-programmes
```

Requires `fieldwork:write`.

```json
{
  "objective": "Determine whether payroll changes were authorised and accurately processed.",
  "controlId": "PAY-CTRL-07",
  "assertions": ["authorisation", "accuracy", "completeness"],
  "population": [
    { "recordId": "PAY-0001", "stratum": "executive", "riskScore": 80 },
    { "recordId": "PAY-0002", "stratum": "staff", "riskScore": 10 }
  ],
  "samplingMethod": "stratified",
  "sampleSize": 2,
  "confidenceLevel": 0.95,
  "tolerableDeviationRate": 0.1,
  "expectedDeviationRate": 0.01,
  "reviewer": "audit.manager.one",
  "testSteps": [
    {
      "stepId": "AUTH-01",
      "title": "Inspect approval",
      "procedure": "Inspect the approved change request and compare it with the payroll master-file change.",
      "required": true
    }
  ]
}
```

The authenticated creator becomes `preparedBy`. The assigned reviewer must be a different identity.

## Record sample execution

```text
POST /api/workforce-audit/test-programmes/{programmeId}/samples/{sampleId}/results
```

Requires `fieldwork:write`.

```json
{
  "stepResults": [
    {
      "stepId": "AUTH-01",
      "outcome": "pass",
      "evidenceRefs": ["EVD-0123456789abcdef0123456789abcdef"],
      "notes": "Approval matched the processed payroll change."
    }
  ],
  "notes": "No exception identified."
}
```

Allowed step outcomes are `pass`, `deviation`, and `not_applicable`. Applicable steps require at least one evidence reference. A `not_applicable` result requires a written rationale.

A later result is an append-only retest. It must include `retestReason`; prior attempts are not overwritten.

The assigned reviewer cannot execute sample testing.

## Submit for review

```text
POST /api/workforce-audit/test-programmes/{programmeId}/submit
```

```json
{
  "rationale": "All selected items were tested and the evidence package is complete.",
  "exceptionsEscalated": true
}
```

Submission is refused unless every selected sample has an executed result. Any `PLH-...` fieldwork placeholder in the latest evidence set blocks submission. Replace placeholders with traceable evidence before review.

## Statistical conclusion

The reviewer conclusion is derived from:

- applicable tested items;
- samples whose latest overall outcome is `deviation`;
- approved tolerable deviation rate;
- approved confidence level;
- one-sided Wilson upper confidence bound.

The result is:

- `ineffective` when the observed deviation rate exceeds tolerance;
- `inconclusive` when observed deviation is within tolerance but the upper bound exceeds tolerance;
- `effective_with_exceptions` when deviations exist and the upper bound remains within tolerance;
- `effective` when no deviations exist and the upper bound remains within tolerance.

Small samples can therefore remain `inconclusive` even with no observed deviations. This is deliberate and prevents a zero-exception small sample from being described as statistically conclusive.

## Finalise review

```text
POST /api/workforce-audit/test-programmes/{programmeId}/review
```

Requires `engagement:write`, which is limited to audit managers and compliance administrators in the default roles. The authenticated identity must also exactly match the programme's assigned reviewer and must not have executed any sample attempt.

```json
{
  "conclusion": "effective_with_exceptions",
  "rationale": "Independent review confirms the population, execution evidence, deviations, and derived conclusion.",
  "confirmation": "FINALISE TPG-2026-0001 EFFECTIVE_WITH_EXCEPTIONS"
}
```

The supplied conclusion must equal the statistically derived conclusion. Management preference cannot override the recorded metrics through this endpoint.

## Read routes

```text
GET /api/workforce-audit/test-programmes
GET /api/workforce-audit/test-programmes?engagementId=ENG-2026-004
GET /api/workforce-audit/test-programmes?status=review_pending
GET /api/workforce-audit/test-programmes/{programmeId}
GET /api/workforce-audit/test-programmes/{programmeId}/verify
```

Normal reads require `audit:read`; integrity verification requires `governance:read`.

## Governance events

The ledger records:

- `test_programme.created`;
- `test_sample.executed`;
- `test_sample.retested`;
- `test_programme.submitted`;
- `test_programme.finalised`.

Events contain population/sample counts, population digest, result counts, conclusion metrics, and actor identity. They do not contain evidence content.

## Operating controls

Before relying on a programme conclusion:

1. independently verify population completeness and extraction parameters;
2. preserve the query, report, or source-system evidence used to produce the manifest;
3. review duplicate, missing, and out-of-period records before programme creation;
4. ensure selected record IDs map unambiguously back to source records;
5. verify evidence references and custody integrity;
6. review every deviation and consider whether a finding is required;
7. investigate inconsistent risk scores or strata;
8. run programme integrity verification before report issuance;
9. retain the reviewer rationale and governance events with the engagement file.

A finalised programme is immutable through the current API. Corrections require a new programme or an explicitly governed future amendment workflow; direct history rewriting is not supported.
