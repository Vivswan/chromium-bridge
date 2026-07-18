// Storage-backed domain allowlist + the new-origin approval flow.
//
// The allowlist lives in browser.storage.local (survives SW restarts). A new
// origin surfaces a badge + pending request that the popup resolves.

import { AllowlistSchema } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import {
  globToPermissionPattern,
  hostFromOriginGlob,
  matchesAny,
  normalizeCookieDomain,
  originGlobOf,
} from "../shared/allowlist";
import { getSetting } from "../shared/settings";
import { BADGE_PENDING_COLOR } from "../shared/theme-colors";

const STORAGE_KEY = "allowlist";

export async function getAllowlist(): Promise<string[]> {
  const { [STORAGE_KEY]: list } = await browser.storage.local.get(STORAGE_KEY);
  // A record that fails the schema (not an array, or with non-string entries)
  // degrades to the empty allowlist: nothing is allowed - fail closed.
  const parsed = AllowlistSchema.safeParse(list ?? []);
  if (!parsed.success) {
    console.warn("[bb] stored allowlist is malformed; treating it as empty");
    return [];
  }
  return parsed.data;
}

export async function setAllowlist(list: string[]) {
  await browser.storage.local.set({ [STORAGE_KEY]: list });
}

export async function ensureDomainAllowed(domain: string) {
  const host = normalizeCookieDomain(domain);
  if (!host) throw new Error(`invalid cookie domain: ${domain}`);
  // Global bypass: if the user opted into "allow all sites", skip the
  // per-site check entirely.
  if ((await getSetting("allowAllSites")) === true) return;
  const list = await getAllowlist();
  const allowed = list.some((glob) => hostFromOriginGlob(glob) === host);
  if (!allowed) {
    throw new Error(
      `cookie domain not allowed by user: ${domain}. Use a URL for the active allowlisted origin, or approve that exact host first.`,
    );
  }
}

export async function ensureAllowed(url: string | undefined) {
  const glob = originGlobOf(url);
  if (!glob) throw new Error(`cannot parse url: ${url}`);
  // Global bypass: if the user opted into "allow all sites", skip the
  // per-site prompt entirely. The <all_urls> host permission must have been
  // granted when they enabled the toggle (see options.ts), so content-script
  // injection works on any origin.
  if ((await getSetting("allowAllSites")) === true) return;
  const list = await getAllowlist();
  if (matchesAny(glob, list)) return;
  // Not allowlisted → ask the user via the popup. We open the popup by
  // setting a badge and storing a pending request; the popup, when opened,
  // reads it. If the popup isn't opened within the timeout, we reject.
  const allowed = await promptUserForAllow(glob);
  if (!allowed) {
    throw new Error(`origin not allowed by user: ${glob}`);
  }
}

// Ask the user to approve a new origin. We surface a notification badge; the
// popup handles the actual yes/no. Resolves true/false.
function promptUserForAllow(glob: string): Promise<boolean> {
  return new Promise((resolve) => {
    const reqId = `allow_${Date.now()}`;
    pendingAllowRequests.set(reqId, { glob, resolve });
    browser.action.setBadgeText({ text: "!" });
    // Amber, not red: a new-origin approval is a pending "needs you" state
    // in the Control Tower vocabulary (red is kill/deny only).
    browser.action.setBadgeBackgroundColor({ color: BADGE_PENDING_COLOR });
    browser.storage.local.set({ pendingAllow: { id: reqId, glob } });
    // Auto-reject after 60s.
    setTimeout(() => {
      if (pendingAllowRequests.has(reqId)) {
        pendingAllowRequests.delete(reqId);
        browser.storage.local.remove("pendingAllow");
        maybeClearBadge();
        resolve(false);
      }
    }, 60000);
  });
}

const pendingAllowRequests = new Map<string, { glob: string; resolve: (v: boolean) => void }>();

function maybeClearBadge() {
  if (pendingAllowRequests.size === 0) {
    browser.action.setBadgeText({ text: "" });
  }
}

// Resolve a pending approval (called by the popup via the message router).
export async function resolvePendingAllow(
  id: string,
  allow: boolean,
): Promise<{ ok: boolean; error?: string }> {
  const pending = pendingAllowRequests.get(id);
  if (!pending) return { ok: false, error: "no such pending request" };
  pendingAllowRequests.delete(id);
  browser.storage.local.remove("pendingAllow");
  maybeClearBadge();
  if (allow) {
    const list = await getAllowlist();
    if (!list.includes(pending.glob)) list.push(pending.glob);
    await setAllowlist(list);
    pending.resolve(true);
  } else {
    pending.resolve(false);
  }
  return { ok: true };
}

// Manual add from the options page. We only persist the glob — MV3 forbids
// browser.permissions.request outside a user-gesture context, so the actual
// host permission is requested on first visit via ensureAllowed().
export async function addAllow(
  input: string,
): Promise<{ ok: boolean; list?: string[]; error?: string }> {
  const glob = canonicalOriginGlob(input);
  if (!glob) return { ok: false, error: `not a valid http(s) origin: ${input}` };
  const list = await getAllowlist();
  if (!list.includes(glob)) list.push(glob);
  await setAllowlist(list);
  return { ok: true, list };
}

/** Reduce any user-submitted URL/origin to protocol://host/* for an http(s)
 * origin, dropping path/query/credentials, or null if it is not one. Central
 * validation so the allowlist cannot be seeded with a malformed entry no
 * ensureAllowed check would ever match, regardless of which surface adds it. */
export function canonicalOriginGlob(input: unknown): string | null {
  if (typeof input !== "string" || !input.trim()) return null;
  const glob = originGlobOf(input.trim());
  if (!glob) return null;
  return /^https?:\/\//i.test(glob) ? glob : null;
}

// Remove a glob and best-effort release its host permission.
export async function removeAllow(glob: string): Promise<{
  list: string[];
  permissionRemoved: boolean;
  permissionError?: string;
}> {
  const list = await getAllowlist();
  const next = list.filter((g) => g !== glob);
  await setAllowlist(next);
  const pattern = globToPermissionPattern(glob);
  if (!pattern) return { list: next, permissionRemoved: false };
  try {
    const removed = await browser.permissions.remove({ origins: [pattern] });
    return { list: next, permissionRemoved: Boolean(removed) };
  } catch (e) {
    return {
      list: next,
      permissionRemoved: false,
      permissionError: e instanceof Error ? e.message : String(e),
    };
  }
}
