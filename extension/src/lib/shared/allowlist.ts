// Pure allowlist / origin-glob helpers.
//
// Extracted from background.ts so they can be unit-tested without a browser.
// The browser.storage-backed read/write of the allowlist stays in background.ts;
// only the pure string logic lives here.

// Derive the origin glob ("https://host/*") for a URL, or null if unparsable.
export function originGlobOf(url: string | undefined): string | null {
  try {
    const u = new URL(url!);
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

// Extract the lowercase host from an origin glob, or null if unparsable.
export function hostFromOriginGlob(glob: string): string | null {
  try {
    return new URL(glob.replace(/\*$/, "")).host.toLowerCase();
  } catch {
    return null;
  }
}

// Normalize a user-supplied cookie domain to a bare lowercase host, or null if
// it is not a plain domain (contains scheme/path/glob).
export function normalizeCookieDomain(domain: unknown): string | null {
  if (typeof domain !== "string") return null;
  let d = domain.trim().toLowerCase();
  if (!d || d.includes("://") || d.includes("/") || d.includes("*")) return null;
  while (d.startsWith(".")) d = d.slice(1);
  return d || null;
}

// Does `glob` match any pattern in `list`?
export function matchesAny(glob: string, list: string[]): boolean {
  return list.some((pattern) => simpleMatch(pattern, glob));
}

// Minimal glob match: supports a trailing * only. Good enough for "host/*".
export function simpleMatch(pattern: string, target: string): boolean {
  if (pattern === target) return true;
  if (pattern.endsWith("/*")) {
    const base = pattern.slice(0, -2); // drop "/*"
    return target === base || target.startsWith(`${base}/`);
  }
  if (pattern.endsWith("*")) {
    return target.startsWith(pattern.slice(0, -1));
  }
  return false;
}

// Convert an origin glob to a browser.permissions match pattern, or null.
export function globToPermissionPattern(glob: string): string | null {
  if (typeof glob !== "string" || !glob) return null;
  return glob.endsWith("/*") ? glob : `${glob}*`;
}
