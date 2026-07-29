# Workforce audit recovery runbook

## Create and verify a recovery point

1. Authenticate as an `audit_manager` or `compliance_admin`.
2. Create a backup with a specific operational reason.
3. Record the returned backup ID, key ID, checksum, and creation time.
4. Verify the backup before treating it as recoverable.
5. Confirm retention pruning did not remove a required recovery point.

## Dry-run a restore

1. Retrieve the current governance integrity result and record its `headHash`.
2. Submit a restore request with the backup ID, reason, current `headHash`, and `dryRun: true`.
3. Compare current and backup engagement, finding, and governance-event counts.
4. Confirm the backup checksum and encrypted snapshot validation succeeded.
5. Obtain the required operational approval before execution.

## Execute a restore

1. Retrieve the governance head again immediately before execution.
2. Submit `dryRun: false`, the fresh head hash, and `confirmation: "RESTORE <backupId>"`.
3. Confirm the response identifies both the restored backup and the automatic safety backup.
4. Verify governance integrity after restoration.
5. Review the final `backup.restored` governance event.
6. Preserve the safety backup until the recovery outcome is accepted.

## Failure response

- Stop retrying when `BACKUP_INTEGRITY_FAILED` is returned; investigate the encrypted file, manifest, keyring, and storage medium.
- Refresh the governance head after `RECOVERY_CONFLICT`; do not bypass the conflict check.
- Treat `BACKUP_UNAVAILABLE` or `PERSISTENCE_UNAVAILABLE` as a failed recovery operation, not a partial success.
- If automatic rollback reports failure, isolate the application process and recover from the reported safety backup before accepting further writes.
