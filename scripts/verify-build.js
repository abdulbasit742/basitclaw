import { access, readFile } from 'node:fs/promises';

const requiredFiles = [
  'src/server.js', 'src/federatedServer.js', 'src/runtime.js',
  'src/security/accessControl.js', 'src/security/authenticationGateway.js',
  'src/security/federatedIdentity.js', 'src/security/oidcAuthenticator.js',
  'src/security/identityEntitlementRegistry.js', 'src/security/scimAccessController.js',
  'src/security/scimHandler.js', 'src/security/privilegedAccessRegistry.js',
  'src/security/privilegedAccessHandler.js', 'src/security/rateLimiter.js',
  'src/security/sharedRateLimiter.js', 'src/security/fileMutex.js',
  'src/security/securityTelemetry.js', 'src/security/securityArchiveCodec.js',
  'src/security/securityArchiveFilesystem.js', 'src/security/securityEventArchive.js',
  'src/security/securityKeyLifecycle.js', 'src/security/securityAlertCodec.js',
  'src/security/securityAlertOutbox.js', 'src/security/securityAlertDispatcher.js',
  'src/security/securityAlertRuntime.js', 'scripts/generate-api-credential.js',
  'scripts/generate-scim-credential.js', 'scripts/identity-check.js',
  'scripts/identity-entitlements.js', 'scripts/security-alerts.js', 'scripts/security-keys.js',
  'src/persistence/encryptedSnapshotStore.js', 'src/persistence/backupManager.js',
  'src/resilience/replicaManager.js', 'src/resilience/resilienceScheduler.js',
  'src/coordination/fileLeaseCoordinator.js', 'src/coordination/fencedSnapshotStore.js',
  'src/coordination/coordinatedRegistry.js', 'src/services/workforceAuditService.js',
  'src/services/workforceAuditRegistry.js', 'src/services/governanceLedger.js',
  'public/workforce-audit.html', 'src/types/workforceAudit.d.ts',
  'src/types/coordination.d.ts', 'src/types/security.d.ts', 'src/types/identity.d.ts',
  'docs/api-security.md', 'docs/identity-federation.md', 'docs/identity-provisioning.md',
  'docs/privileged-access.md', 'docs/security-alert-delivery.md', 'docs/security-key-rotation.md',
  '.github/workflows/ci.yml', 'test/identityEntitlementRegistry.test.js',
  'test/authenticationEntitlements.test.js', 'test/scimAccessController.test.js',
  'test/scimProvisioning.test.js', 'test/identityLifecycleRuntime.test.js',
  'test/dashboardIdentityLifecycle.test.js', 'test/privilegedAccessRegistry.test.js',
  'test/privilegedAccessIntegration.test.js'
];

for (const file of requiredFiles) await access(new URL(`../${file}`, import.meta.url));

async function requireMarkers(path, label, markers) {
  const content = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
  for (const marker of markers) {
    if (!content.includes(marker)) throw new Error(`${label} build verification failed: missing ${marker}.`);
  }
}

await requireMarkers('src/persistence/encryptedSnapshotStore.js', 'Persistence', ['aes-256-gcm', 'writeEncrypted', 'inspectEncrypted', 'serialize', 'WORKFORCE_AUDIT_PRIMARY_KEY_ID']);
await requireMarkers('src/persistence/backupManager.js', 'Backup', ['checksumSha256', 'BACKUP_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_BACKUP_RETENTION', 'safety']);
await requireMarkers('src/resilience/replicaManager.js', 'Replica', ['encrypted-file-replica', 'REPLICA_INTEGRITY_FAILED', 'WORKFORCE_AUDIT_REPLICA_DIR', 'idempotent']);
await requireMarkers('src/coordination/fileLeaseCoordinator.js', 'Coordination', ['WRITE_COORDINATION_BUSY', 'fencingToken', 'stale', 'WORKFORCE_AUDIT_COORDINATION_MODE']);
await requireMarkers('src/coordination/fencedSnapshotStore.js', 'Fencing', ['PERSISTENCE_FENCE_REJECTED', 'snapshot.fenced', 'latestFencingToken', 'bindFencingToken']);
await requireMarkers('src/coordination/coordinatedRegistry.js', 'Coordinated registry', ['createRuntimeWorkforceAuditRegistry', 'createReadOnlyStore', 'getCoordinationStatus', 'createRegistry']);
await requireMarkers('src/resilience/resilienceScheduler.js', 'Scheduler', ['WORKFORCE_AUDIT_SCHEDULED_BACKUP_MINUTES', 'runResilienceCycle', 'unref']);
await requireMarkers('src/security/accessControl.js', 'Credential', ['scryptSync', 'CREDENTIAL_REVOKED', 'credentialHealth', 'privileged:approve']);
await requireMarkers('src/security/authenticationGateway.js', 'Authentication gateway', ['api-key', 'oidc', 'hybrid', 'privilegedAccessRegistry', 'privilegedAccess.authorise']);
await requireMarkers('src/security/federatedIdentity.js', 'Federated identity', ['deriveFederatedSubject', 'externalSubjectHash', 'exactIssuer']);
await requireMarkers('src/security/oidcAuthenticator.js', 'OIDC authenticator', ['RS256', 'ES256', 'OIDC_AUDIENCE_INVALID', 'OIDC_TENANT_NOT_ALLOWED', 'OIDC_AMR_REQUIRED', 'JWKS response exceeds']);
await requireMarkers('src/security/identityEntitlementRegistry.js', 'Identity entitlement registry', ['aes-256-gcm', 'IDENTITY_NOT_PROVISIONED', 'IDENTITY_REVIEW_OVERDUE', 'reviewStatus', 'WORKFORCE_AUDIT_IDENTITY_STORE_KEYS']);
await requireMarkers('src/security/scimAccessController.js', 'SCIM access', ['scrypt(', 'SCIM_CREDENTIAL_REVOKED', 'explicit scopes array', 'WORKFORCE_AUDIT_SCIM_CREDENTIALS']);
await requireMarkers('src/security/scimHandler.js', 'SCIM protocol', ['/scim/v2/Users', 'If-Match', 'WORKFORCE_EXTENSION', 'identity.deprovisioned', 'invalid percent encoding']);
await requireMarkers('src/security/privilegedAccessRegistry.js', 'Privileged access registry', ['aes-256-gcm', 'PRIVILEGED_ACCESS_REQUIRED', 'PRIVILEGED_ACCESS_SELF_APPROVAL_DENIED', 'BREAK_GLASS_CONFIRMATION_REQUIRED', 'WORKFORCE_AUDIT_PRIVILEGED_ACCESS_KEYS']);
await requireMarkers('src/security/privilegedAccessHandler.js', 'Privileged access API', ['/privileged-access', 'If-Match', 'privileged_access.break_glass_activated', 'PRIVILEGED_ACCESS_PRECONDITION_REQUIRED']);
await requireMarkers('src/federatedServer.js', 'Federated server', ['createScimHandler', 'createPrivilegedAccessHandler', 'protectedPermissionFor', 'privileged_access.unavailable']);
await requireMarkers('src/runtime.js', 'Runtime', ['prepareIdentityProvider', 'prepareIdentityLifecycle', 'PRIVILEGED_ACCESS_STORE_UNAVAILABLE', 'SCIM_UNAVAILABLE', 'startRuntime']);
await requireMarkers('scripts/identity-check.js', 'Identity preflight', ['runIdentityCheck', 'identityEntitlements', 'scim']);
await requireMarkers('scripts/generate-scim-credential.js', 'SCIM credential generator', ['presentedToken', 'parseScimCredentialArguments', '--scopes', 'secret manager']);
await requireMarkers('scripts/identity-entitlements.js', 'Identity lifecycle CLI', ['review-status', 'listEvents', 'IDENTITY_ENTITLEMENT_COMMAND_FAILED']);
await requireMarkers('src/security/rateLimiter.js', 'Rate limit', ['RATE_LIMITED', 'shared-file', 'WORKFORCE_AUDIT_DISTRIBUTED_RATE_LIMIT_REQUIRED', 'WORKFORCE_AUDIT_TRUST_PROXY_HOPS']);
await requireMarkers('src/security/sharedRateLimiter.js', 'Shared rate limit', ['shared-file-fixed-window', 'RATE_LIMIT_STORE_UNAVAILABLE', 'identityHash', 'atomicWriteJson']);
await requireMarkers('src/security/fileMutex.js', 'Security mutex', ['SECURITY_CONTROL_BUSY', 'stale', 'owner.json', 'withLock']);
await requireMarkers('src/security/securityEventArchive.js', 'Security archive', ['SECURITY_ARCHIVE_INTEGRITY_FAILED', 'shared-file-encrypted-hash-chain', 'prunePlanPath', 'recoverHeadLocked']);
await requireMarkers('src/security/securityArchiveCodec.js', 'Security archive codec', ['aes-256-gcm', 'WORKFORCE_AUDIT_SECURITY_ARCHIVE_KEYS', 'primaryKeyId', 'identifySignedKey', 'ciphertext']);
await requireMarkers('src/security/securityKeyLifecycle.js', 'Security key lifecycle', ['archiveCanRetire', 'retainedHistoricalKeyIds', 'lifecycle_unavailable', 'receiver_overlap_confirmation_required']);
await requireMarkers('src/security/securityAlertCodec.js', 'Security alert codec', ['x-basitclaw-signature', 'x-basitclaw-key-id', 'WORKFORCE_AUDIT_SECURITY_ALERT_SIGNING_SECRETS', 'primarySigningKeyId']);
await requireMarkers('src/security/securityAlertOutbox.js', 'Security alert outbox', ['shared-file-durable-outbox', 'dead-letter', 'claimExpiresAt', 'commitDestination']);
await requireMarkers('src/security/securityAlertDispatcher.js', 'Security alert dispatcher', ['signed-webhook-durable-outbox', 'SECURITY_ALERT_DELIVERY_UNAVAILABLE', 'dispatchDue', 'maximum_attempts_exceeded']);
await requireMarkers('src/security/securityAlertRuntime.js', 'Security alert runtime', ['WORKFORCE_AUDIT_SECURITY_ALERT_AUTO_START', 'WORKFORCE_AUDIT_SECURITY_ALERT_DEAD_LETTER_RETENTION', 'createSecurityAlertOutbox']);
await requireMarkers('src/security/securityTelemetry.js', 'Security telemetry', ['bounded-memory-plus-encrypted-archive', 'listArchived', 'keyLifecycle', 'redactLifecycle', 'redactOperationalPaths']);
await requireMarkers('docs/identity-federation.md', 'Identity federation runbook', ['hybrid', 'entitlement', 'identity:check', 'OIDC_UNAVAILABLE']);
await requireMarkers('docs/identity-provisioning.md', 'Identity provisioning runbook', ['SCIM', 'If-Match', 'IDENTITY_REVIEW_OVERDUE', 'identity:entitlements']);
await requireMarkers('docs/privileged-access.md', 'Privileged access runbook', ['dual approval', 'BREAK GLASS', 'If-Match', 'post-use review']);
await requireMarkers('docs/security-alert-delivery.md', 'Security alert runbook', ['at least once', 'x-basitclaw-key-id', 'dead-letter', 'deduplicate']);
await requireMarkers('docs/security-key-rotation.md', 'Security key rotation runbook', ['archive-can-retire', 'alert-can-retire', '--receiver-confirmed', 'missingKeyIds']);
await requireMarkers('src/server.js', 'Server', ['/backups', 'backup:restore', 'security-archive-events', 'security-archive-integrity', 'RateLimitStoreError', 'publicSecurityHealth']);
await requireMarkers('public/workforce-audit.html', 'Dashboard', ['OIDC bearer token', 'Identity lifecycle', 'Privileged access', 'JIT grants active', 'Break-glass reviews overdue', 'API Security Events']);

console.log('Build verification passed.');
