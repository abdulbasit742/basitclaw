import { randomBytes, scryptSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export function generateScimCredential({ keyId, subject, expiresAt = null, scopes = ['scim:read', 'scim:write'] } = {}) {
  const safeKeyId = identifier(keyId, 'keyId');
  const safeSubject = identifier(subject, 'subject');
  const safeScopes = [...new Set((Array.isArray(scopes) ? scopes : String(scopes ?? '').split(',')).map((item) => String(item).trim()).filter(Boolean))];
  if (safeScopes.length === 0 || safeScopes.some((scope) => !['scim:read', 'scim:write'].includes(scope))) throw new TypeError('scopes must contain scim:read and/or scim:write.');
  const expiry = expiresAt ? new Date(expiresAt) : null;
  if (expiry && Number.isNaN(expiry.getTime())) throw new TypeError('expiresAt must be a valid date.');
  const secret = randomBytes(32).toString('base64url');
  const salt = randomBytes(24).toString('base64url');
  const secretHash = scryptSync(secret, salt, 32).toString('base64');
  return {
    presentedToken: `${safeKeyId}.${secret}`,
    record: {
      keyId: safeKeyId,
      subject: safeSubject,
      salt,
      secretHash,
      scopes: safeScopes,
      status: 'active',
      ...(expiry ? { expiresAt: expiry.toISOString() } : {})
    }
  };
}

function identifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(text)) throw new TypeError(`${field} must be a safe identifier.`);
  return text;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const [keyId, subject, expiresAt, scopes] = process.argv.slice(2);
    const output = generateScimCredential({ keyId, subject, expiresAt: expiresAt || null, scopes: scopes ? scopes.split(',') : undefined });
    console.log(JSON.stringify(output, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ success: false, code: 'SCIM_CREDENTIAL_GENERATION_FAILED', error: error.message }));
    process.exitCode = 1;
  }
}
