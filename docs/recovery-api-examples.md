# Recovery API examples

All requests require `x-api-key`.

## Create a recovery point

```http
POST /api/workforce-audit/backups
Content-Type: application/json

{"reason":"Approved pre-release recovery point"}
```

## Verify a recovery point

```http
POST /api/workforce-audit/backups/BAK-20260729110000-1234abcd/verify
Content-Type: application/json

{}
```

## Dry-run a restore

```http
POST /api/workforce-audit/backups/BAK-20260729110000-1234abcd/restore
Content-Type: application/json

{"reason":"Validate the approved recovery point","expectedHeadHash":"<current-governance-head>","dryRun":true}
```

## Execute a restore

```http
POST /api/workforce-audit/backups/BAK-20260729110000-1234abcd/restore
Content-Type: application/json

{"reason":"Recover to the approved control state","expectedHeadHash":"<fresh-current-governance-head>","dryRun":false,"confirmation":"RESTORE BAK-20260729110000-1234abcd"}
```
