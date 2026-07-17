// Shared sensitive-data masking.
//
// The JWT/hex/number/bearer pattern catalogue was previously duplicated
// verbatim between background.ts (maskCookieValue) and content.ts
// (maskString). It is unified here. NOTE the two entry points are deliberately
// NOT identical: `maskString` additionally full-masks a value that *looks* like
// a bare credential, while `maskCookieValue` applies only the pattern catalogue
// (cookies are structured; a full-mask would hide too much). Preserve that.

// Keys/values whose name hints at a secret.
export const SENSITIVE_KEY = /(token|cookie|password|passwd|secret|api[_-]?key|auth|cred|session)/i;

// Apply the credential-pattern catalogue to a string (no length guard). Shared
// core of both maskString and maskCookieValue. This is a heuristic, best-effort
// filter (see SECURITY.md): it targets common secret shapes (JWT, long hex,
// long digit runs, opaque base64url tokens, bearer/key assignments) and will
// not catch every possible secret format.
export function maskPatterns(s: string): string {
  let out = s;
  // JWT (eyJ... . ... . ...)
  out = out.replace(/ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "••••[jwt]");
  // Long hex (>=32): secrets, hashes, API keys
  out = out.replace(/\b[a-fA-F0-9]{32,}\b/g, "••••[hex]");
  // Long digit runs (>=12): card numbers, account ids
  out = out.replace(/\b\d{12,}\b/g, "••••[num]");
  // Opaque tokens (base64url / random ids, >=32 chars containing BOTH a letter
  // and a digit): session tokens and API keys that are not in JWT or bare-hex
  // form. Runs after the hex/digit rules so those keep their specific tags. We
  // match the candidate run with a single greedy pass, then test it in the
  // callback: this stays linear-time (no nested lookaheads re-scanning at every
  // word boundary, which would be quadratic on adversarial input). The
  // letter+digit requirement keeps it off long natural-language words.
  // Best-effort only (see maskPatterns note / SECURITY.md).
  out = out.replace(/\b[A-Za-z0-9_-]{32,}\b/g, (m) =>
    /[A-Za-z]/.test(m) && /\d/.test(m) ? "••••[token]" : m
  );
  // Bearer / key-like patterns
  out = out.replace(
    /(?:bearer|token|password|secret|api[_-]?key)\s*[:=]\s*\S+/gi,
    "••••[redacted]"
  );
  return out;
}

// Content-script string masking: short values pass through; otherwise apply the
// catalogue, then full-mask if the whole string reads like a bare credential.
export function maskString(s: string): string {
  if (s.length < 8) return s;
  const out = maskPatterns(s);
  if (SENSITIVE_KEY.test(s) && s.length >= 8 && !/\s/.test(s)) {
    return "••••[sensitive]";
  }
  return out;
}

// Cookie value masking: non-strings and short values pass through unchanged;
// otherwise apply only the pattern catalogue (no full-mask — see note above).
export function maskCookieValue(v: unknown): unknown {
  if (typeof v !== "string") return v;
  if (v.length < 8) return v;
  return maskPatterns(v);
}

// Mask a long integer that looks card-like / id-like.
export function maskNumber(n: number): number | string {
  if (Number.isInteger(n) && Math.abs(n) >= 1e11) return "••••[num]";
  return n;
}

// Mask a key NAME (not value) when it hints at a secret.
export function maskKeyName(key: string): string {
  return SENSITIVE_KEY.test(key) ? "••••" + key.slice(-2) : key;
}

// Recursively mask an arbitrary JSON-ish value (strings, numbers, arrays,
// objects). Used for eval results and storage dumps.
export function maskSensitive(value: any): any {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === "string") return maskString(value);
  if (t === "number") return maskNumber(value);
  if (t === "boolean") return value;
  if (Array.isArray(value)) return value.map(maskSensitive);
  if (t === "object") {
    const out: any = {};
    for (const k of Object.keys(value)) {
      out[maskKeyName(k)] = maskSensitive(value[k]);
    }
    return out;
  }
  return value;
}
