import { createHash } from 'node:crypto';

export function deriveFederatedSubject(issuer, externalSubject) {
  const expectedIssuer = exactIssuer(issuer);
  const subjectClaim = String(externalSubject ?? '');
  if (!subjectClaim || subjectClaim.length > 512) throw new TypeError('externalSubject must contain from 1 to 512 characters.');
  const subjectHash = createHash('sha256').update(`${expectedIssuer}|${subjectClaim}`).digest('hex');
  return Object.freeze({
    subject: `oidc-${subjectHash.slice(0, 24)}`,
    externalSubjectHash: subjectHash.slice(0, 24)
  });
}

export function exactIssuer(value) {
  let url;
  try { url = new URL(String(value ?? '')); } catch { throw new TypeError('issuer must be a valid URL.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search) {
    throw new TypeError('issuer must be an HTTPS URL without credentials, query, or fragment.');
  }
  return url.toString().replace(/\/$/, '');
}
