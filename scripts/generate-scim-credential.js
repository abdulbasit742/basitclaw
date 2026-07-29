import { randomBytes, scryptSync } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export function generateScimCredential({ keyId, subject, expiresAt = null, scopes = ['scim:read', 'scim:write'] } = {}) {
  const safeKeyId = identifier(keyId, 'keyId');
  const safeSubject = identifier(subject, 'subject');
  const safeScopes = parseScopes(scopes);
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

export function parseScimCredentialArguments(argv = []) {
  const positional = [];
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--expires-at') {
      options.expiresAt = requiredOption(argv[++index], '--expires-at');
    } else if (value === '--scopes') {
      options.scopes = requiredOption(argv[++index], '--scopes');
    } else if (String(value).startsWith('--')) {
      throw new TypeError(`Unsupported option: ${value}`);
    } else {
      positional.push(value);
    }
  }
  if (positional.length < 2 || positional.length > 4) {
    throw new TypeError('Usage: <keyId> <subject> [expiresAt] [scopes] [--expires-at <date>] [--scopes <csv>].');
  }
  const [keyId, subject, legacyExpiresAt, legacyScopes] = positional;
  if (options.expiresAt && legacyExpiresAt) throw new TypeError('expiresAt must be supplied either positionally or with --expires-at, not both.');
  if (options.scopes && legacyScopes) throw new TypeError('scopes must be supplied either positionally or with --scopes, not both.');
  return {
    keyId,
    subject,
    expiresAt: options.expiresAt ?? legacyExpiresAt ?? null,
    scopes: options.scopes ?? legacyScopes ?? undefined
  };
}

function parseScopes(value) {
  const items = Array.isArray(value) ? value : String(value ?? '').split(',');
  const scopes = [...new Set(items.map((item) => String(item).trim()).filter(Boolean))];
  if (scopes.length === 0 || scopes.some((scope) => !['scim:read', 'scim:write'].includes(scope))) {
    throw new TypeError('scopes must contain scim:read and/or scim:write.');
  }
  return scopes;
}

function identifier(value, field) {
  const text = String(value ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(text)) throw new TypeError(`${field} must be a safe identifier.`);
  return text;
}

function requiredOption(value, option) {
  if (!value || String(value).startsWith('--')) throw new TypeError(`${option} requires a value.`);
  return value;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const output = generateScimCredential(parseScimCredentialArguments(process.argv.slice(2)));
    console.error('Warning: presentedToken is displayed once. Store it in an approved secret manager and never in WORKFORCE_AUDIT_SCIM_CREDENTIALS.');
    console.log(JSON.stringify(output, null, 2));
  } catch (error) {
    console.error(JSON.stringify({ success: false, code: 'SCIM_CREDENTIAL_GENERATION_FAILED', error: error.message }));
    process.exitCode = 1;
  }
}
