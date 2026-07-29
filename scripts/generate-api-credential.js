import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { hashApiKeySecret, permissionsForRole } from '../src/security/accessControl.js';

export function generateApiCredential({ keyId, subject, tenantId, role = 'audit_viewer', status = 'active', notBefore = null, expiresAt = null } = {}) {
  const safeKeyId = safeIdentifier(keyId, 'keyId');
  const safeSubject = safeIdentifier(subject, 'subject');
  const safeTenantId = safeIdentifier(tenantId, 'tenantId');
  permissionsForRole(role);
  if (!['active', 'retiring'].includes(status)) throw new TypeError('Generated credential status must be active or retiring.');
  const secret = randomBytes(32).toString('base64url');
  const salt = randomBytes(18).toString('base64url');
  const record = {
    keyId: safeKeyId,
    salt,
    secretHash: hashApiKeySecret(secret, salt),
    subject: safeSubject,
    tenantId: safeTenantId,
    role,
    status
  };
  if (notBefore) record.notBefore = validDate(notBefore, 'notBefore');
  if (expiresAt) record.expiresAt = validDate(expiresAt, 'expiresAt');
  return { presentedKey: `${safeKeyId}.${secret}`, record };
}

function safeIdentifier(value, field) {
  const identifier = String(value ?? '').trim();
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/.test(identifier)) throw new TypeError(`${field} must be a safe identifier.`);
  return identifier;
}

function validDate(value, field) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new TypeError(`${field} must be a valid date.`);
  return date.toISOString();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [keyId, subject, tenantId, role = 'audit_viewer', expiresAt = null] = process.argv.slice(2);
  try {
    const generated = generateApiCredential({ keyId, subject, tenantId, role, expiresAt });
    console.log(JSON.stringify(generated, null, 2));
    console.error('Store presentedKey in a secret manager now. It is not written anywhere else.');
  } catch (error) {
    console.error(`Usage: npm run credential:generate -- <keyId> <subject> <tenantId> [role] [expiresAt]\n${error.message}`);
    process.exitCode = 1;
  }
}
