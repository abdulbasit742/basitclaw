# Security archive and webhook key rotation

## Scope

This runbook covers the workforce-audit security-event archive keyring and signed security-alert webhook keyring. It does not replace managed secret custody, approval, or receiver change control.

## Archive keyring

Configure every key needed to decrypt or authenticate retained archive material, and identify exactly one primary key for new envelopes:

```bash
WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS='{"2026-q3":"<base64-32-byte-key>","2026-q2":"<previous-base64-32-byte-key>"}'
WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID=2026-q3
```

Each envelope carries an authenticated `keyId`. New events use the primary key. Historical events, retention anchors, and interrupted prune journals are verified using the key that created them. The archive hash chain remains continuous across key changes because each new envelope links to the previous envelope hash.

### Rotate an archive key

1. Generate a new independent 32-byte key in the approved secret manager.
2. Add the new key to `WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS` on every process. Keep the current primary unchanged.
3. Run `npm run security-keys -- status` from an instance with the shared archive mounted. Confirm no key is missing and the archive lifecycle is ready.
4. Change `WORKFORCE_AUDIT_SECURITY_ARCHIVE_PRIMARY_KEY_ID` to the new key ID on every process.
5. Restart or roll out all processes. Confirm newly archived events use the new key ID through the administrator archive export.
6. Keep the previous key configured while any retained envelope, retention anchor, or prune journal references it.
7. Run `npm run security-keys -- archive-can-retire <oldKeyId>`.
8. Remove the old key only when the command returns `safe: true`, then re-run archive integrity verification.

A key that is still referenced must not be deleted. Losing it makes retained evidence unverifiable and can degrade required archive readiness.

## Webhook signing keyring

Configure an overlap keyring and one primary key for new webhook signatures:

```bash
WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS='{"2026-q3":"<new-long-random-secret>","2026-q2":"<previous-long-random-secret>"}'
WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID=2026-q3
```

Outbound requests include `x-basitclaw-key-id`. Receivers must choose the matching secret, verify `x-basitclaw-signature`, enforce timestamp freshness, and deduplicate on `x-basitclaw-delivery-id`.

### Rotate a webhook signing key

1. Add the new secret to both sender and receiver keyrings.
2. Keep the previous key primary while confirming the receiver accepts the new key ID.
3. Switch `WORKFORCE_AUDIT_SECURITY_ALERT_PRIMARY_SIGNING_KEY_ID` to the new key.
4. Verify successful deliveries signed with the new key ID.
5. Maintain an overlap period longer than the maximum retry/dead-letter requeue window approved by operations.
6. Run `npm run security-keys -- alert-can-retire <oldKeyId>`. It must return `receiver_overlap_confirmation_required` until external receiver checks are complete.
7. After the receiver owner confirms every accepted endpoint has the new key and the overlap window has elapsed, run `npm run security-keys -- alert-can-retire <oldKeyId> --receiver-confirmed`.
8. Remove the old secret only when the confirmed command returns `safe: true`; update receivers and senders through approved change control.

## Commands

```bash
npm run security-keys -- status
npm run security-keys -- archive-can-retire 2026-q2
npm run security-keys -- alert-can-retire 2026-q2
npm run security-keys -- alert-can-retire 2026-q2 --receiver-confirmed
```

The CLI intentionally prints key IDs but never secret material. Public health and dashboard responses expose only counts and readiness states.

## Failure handling

- `missingKeyIds` means retained archive material references a key absent from configuration. Restore that key from approved custody before any retention or recovery action.
- An invalid anchor or prune-journal signature means evidence integrity cannot be established. Preserve the archive mount and investigate; do not delete files or force readiness.
- A primary key cannot be retired.
- No archive key is declared safe while lifecycle inspection is unavailable.
- A non-primary archive key cannot be retired while its reference count is non-zero.
- Webhook retirement always requires explicit receiver overlap confirmation because receiver key state is external to BasitClaw.

## Legacy migration

`WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEY` and `WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRET` remain supported for compatibility. They report `legacy-single-key` rotation status. Migrate by adding the current value as the first entry in the corresponding keyring, then add a new key and follow the rotation procedure above.
