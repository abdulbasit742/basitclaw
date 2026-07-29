# Recovery security checklist

- Use a current governance head hash for every dry-run and restore.
- Require a compliance administrator for restore execution.
- Verify checksum and decryption before approving recovery.
- Keep historical encryption keys available until all retained backups expire or are re-encrypted.
- Store primary snapshots and backups on restricted durable volumes.
- Replicate approved backups off-host using a separately controlled process.
- Review retention pruning and recovery governance events.
- Preserve the automatic safety backup until recovery acceptance.
- Test recovery regularly in an isolated environment.
