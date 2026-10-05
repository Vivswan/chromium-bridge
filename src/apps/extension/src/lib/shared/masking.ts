// Shared sensitive-data masking. The two entry points differ on purpose: `maskString` also full-masks a value
// that reads like a bare credential, while `maskCookieValue` applies only the pattern catalogue (cookies are
// structured; a full-mask would hide too much).

// Keys/values whose name hints at a secret.
export const SENSITIVE_KEY = /(token|cookie|password|passwd|secret|api[_-]?key|auth|cred|session)/i;

// The credential-pattern catalogue (no length guard), the core of both entry points. Best-effort by design
// (SECURITY.md): common secret shapes only.
export function maskPatterns(s: string): string {
  let out = s;
  // JWT (eyJ... . ... . ...)
  out = out.replace(/ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "••••[jwt]");
  // Long hex (>=32): secrets, hashes, API keys
  out = out.replace(/\b[a-fA-F0-9]{32,}\b/g, "••••[hex]");
  // Long digit runs (>=12): card numbers, account ids
  out = out.replace(/\b\d{12,}\b/g, "••••[num]");
  // Opaque tokens: >=32 chars with BOTH a letter and a digit (keeps it off long words), after the hex/digit rules
  // so those keep their tags. One greedy pass plus a callback test stays linear; a nested lookahead was quadratic
  // on "a-a-a-...".
  out = out.replace(/\b[A-Za-z0-9_-]{32,}\b/g, (m) =>
    /[A-Za-z]/.test(m) && /\d/.test(m) ? "••••[token]" : m,
  );
  // Bearer / key-like patterns
  out = out.replace(
    /(?:bearer|token|password|secret|api[_-]?key)\s*[:=]\s*\S+/gi,
    "••••[redacted]",
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
// otherwise apply only the pattern catalogue (no full-mask - see note above).
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
  return SENSITIVE_KEY.test(key) ? `••••${key.slice(-2)}` : key;
}

// Stringify + mask a caught error for the outer egress paths (content.ts's __error reply, port.ts's
// BridgeResp.error): a message can embed page-derived data (a throwing getter, a CDP exception description).
export function maskErrorMessage(e: unknown): string {
  const message = (e as { message?: unknown } | null | undefined)?.message;
  return maskString(String(message || e || "error"));
}

// Recursively mask an arbitrary JSON-ish value (strings, numbers, arrays,
// objects). Used for eval results and storage dumps.
export function maskSensitive(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return maskString(value);
  if (typeof value === "number") return maskNumber(value);
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map(maskSensitive);
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(rec)) {
      out[maskKeyName(k)] = maskSensitive(rec[k]);
    }
    return out;
  }
  return value;
}
