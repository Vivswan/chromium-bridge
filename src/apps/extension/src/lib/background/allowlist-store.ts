// Storage-backed domain allowlist + the new-origin approval flow.
//
// The allowlist lives in browser.storage.local (survives SW restarts). A new
// origin surfaces a badge + pending request that the popup resolves.

import { AllowlistSchema, type PendingApproval } from "@chromium-bridge/shared";
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
    // Collision-resistant id: two prompts minted in the same millisecond
    // must not shadow each other.
    const reqId = `allow_${crypto.randomUUID()}`;
    const expiresAt = Date.now() + PENDING_ALLOW_TIMEOUT_MS;
    pendingAllowRequests.set(reqId, { glob, expiresAt, resolve });
    void syncPendingMirror();
    // Auto-reject at the deadline the persisted record advertises.
    setTimeout(() => settlePending(reqId, false), PENDING_ALLOW_TIMEOUT_MS);
  });
}

const PENDING_KEY = "pendingAllow";
const PENDING_ALLOW_TIMEOUT_MS = 60_000;

interface PendingResolver {
  glob: string;
  expiresAt: number;
  resolve: (allowed: boolean) => void;
}

// The outstanding approvals, keyed by request id, oldest first. This map is
// the single source of truth; the persisted popup record and the badge are
// DERIVED from it (syncPendingMirror), so the three can never describe
// different outstanding sets. A worker restart drops the resolvers (those
// ops fail with the worker); the persisted expiresAt ages the orphaned
// records out of the popup, and the next sync sweeps them from storage.
const pendingAllowRequests = new Map<string, PendingResolver>();

// Mirror writes are serialized (the audit-log idiom) so two same-tick
// mutations cannot land their storage snapshots out of order; each step
// snapshots the map at write time, so the last write reflects the newest
// state.
let mirrorChain: Promise<void> = Promise.resolve();
/** Re-derive the persisted popup record and the badge from the resolver map
 * (the single source of truth). Exported so SW startup can call it once with
 * an EMPTY map: that sweeps a ghost record a previous worker life left in
 * storage - whether it is the current shape (its resolver died with the
 * worker) or an old/unparsable shape (which would otherwise leave the badge
 * stuck at "!" and let the popup's Allow request a host permission for an
 * origin the SW then refuses). */
export function syncPendingMirror(): Promise<void> {
  mirrorChain = mirrorChain.then(async () => {
    try {
      const pending: PendingApproval[] = [...pendingAllowRequests.entries()].map(([id, p]) => ({
        id,
        glob: p.glob,
        expiresAt: p.expiresAt,
      }));
      if (pending.length === 0) {
        await browser.storage.local.remove(PENDING_KEY);
        await browser.action.setBadgeText({ text: "" });
      } else {
        await browser.storage.local.set({ [PENDING_KEY]: pending });
        await browser.action.setBadgeText({ text: "!" });
        // Amber, not red: a new-origin approval is a pending "needs you"
        // state in the Control Tower vocabulary (red is kill/deny only).
        await browser.action.setBadgeBackgroundColor({ color: BADGE_PENDING_COLOR });
      }
    } catch (e) {
      // Display-only bookkeeping: the resolver map stays authoritative.
      console.warn("[bb] pending-approval mirror update failed", e);
    }
  });
  return mirrorChain;
}

/** Claim one outstanding approval - SYNCHRONOUSLY, before any await, so the
 * deadline and a concurrent resolution can never both win the same request -
 * and re-derive the mirror and badge from what remains. The only route out
 * of the map: exactly one caller gets the resolver, everyone else gets null. */
function claimPending(id: string): PendingResolver | null {
  const pending = pendingAllowRequests.get(id);
  if (!pending) return null;
  pendingAllowRequests.delete(id);
  void syncPendingMirror();
  return pending;
}

/** Settle one outstanding approval: claim it, then resolve its waiter. */
function settlePending(id: string, allowed: boolean): boolean {
  const pending = claimPending(id);
  if (!pending) return false;
  pending.resolve(allowed);
  return true;
}

// Resolve a pending approval (called by the popup via the message router).
export async function resolvePendingAllow(
  id: string,
  allow: boolean,
): Promise<{ ok: boolean; error?: string }> {
  // Claim before the allowlist I/O below: with the claim taken only after
  // an await, the deadline could settle this request false mid-persist and
  // an approval would land AFTER its denial.
  const pending = claimPending(id);
  if (!pending) {
    // Unknown id - usually a record a previous worker life left behind (its
    // resolver died with that worker). Re-deriving the mirror sweeps such
    // ghosts off the popup and the badge.
    await syncPendingMirror();
    return { ok: false, error: "no such pending request" };
  }
  // Persist the grant BEFORE resolving the waiter, so the op it unblocks
  // finds the allowlist already updated.
  if (allow) {
    try {
      const list = await getAllowlist();
      if (!list.includes(pending.glob)) list.push(pending.glob);
      await setAllowlist(list);
    } catch (e) {
      // The grant could not be persisted: deny rather than unblock an op
      // whose origin was never recorded.
      pending.resolve(false);
      return { ok: false, error: `could not persist the grant: ${String(e)}` };
    }
  }
  pending.resolve(allow);
  return { ok: true };
}

// Manual add from the options page. We only persist the glob - MV3 forbids
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
