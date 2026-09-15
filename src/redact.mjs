// Best effort for structured secrets and common patterns; not a DLP guarantee.
const secretKey = /^(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|secret|api[-_]?key|access[-_]?token|refresh[-_]?token|token|session(?:id)?|csrf[-_]?token|client[-_]?secret)$/i;
export function redactText(input) {
  return String(input)
    .replace(/\b(Bearer|Basic)\s+([A-Za-z0-9+/_=.-]+)/gi, (match, scheme, credential) => {
      if (scheme.toLowerCase() === 'bearer') return '[REDACTED_AUTH]';
      // "basic CSP" is ordinary prose, not a Basic authorization credential.
      return /^[A-Za-z0-9+/]+={0,2}$/.test(credential) && Buffer.from(credential, 'base64').toString().includes(':') ? '[REDACTED_AUTH]' : match;
    })
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED_JWT]')
    .replace(/((?:["']?)(?:password|passwd|secret|api[-_]?key|access[-_]?token|refresh[-_]?token|token|sessionid|client[-_]?secret)(?:["']?)\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s<>&,;]+)/gi, '$1[REDACTED]')
    .replace(/([?&][^=\s&#]+)=([^&#\s"'<>]*)/g, '$1=[REDACTED_QUERY]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED_EMAIL]')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, '[REDACTED_PRIVATE_KEY]')
    .replace(/\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b/g, '[REDACTED_KEY]');
}
export function redact(value) {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, secretKey.test(key) ? '[REDACTED]' : redact(val)]));
  return value;
}
