// CdpSessionRegistry - a module-level singleton mapping tabId → CdpSession.
//
// In CDP mode the debugger stays attached across ops (the "Started debugging
// this browser" banner persists - by design, ADR-0017), so we cache one
// attached session per tab and reuse it. Sessions are torn down when the tab
// closes, when Chrome detaches us, or when the user turns CDP mode off.

import { browser } from "wxt/browser";
import { getEffectivePolicy } from "../effective-policy";
import { POLICY_STORAGE_KEYS } from "../policy-sync";
import { CdpSession } from "./session";

class CdpSessionRegistry {
  private sessions = new Map<number, CdpSession>();

  // Get (creating + attaching lazily) the session for a tab. attach() is
  // idempotent, so this is cheap on the hot path.
  async get(tabId: number): Promise<CdpSession> {
    let session = this.sessions.get(tabId);
    if (!session) {
      // Wire the orphan-cleanup identity guard: a session may issue the
      // tab-scoped cleanup detach only while it is still THIS tab's session
      // (or the tab has none) - never when a newer session has replaced it,
      // whose live attach the stale cleanup would otherwise rip down.
      const created: CdpSession = new CdpSession(tabId, () => {
        const current = this.sessions.get(tabId);
        return current === undefined || current === created;
      });
      session = created;
      this.sessions.set(tabId, session);
    }
    try {
      await session.attach();
    } catch (e) {
      // Attach failed → don't leave a half-dead session cached. But if a
      // concurrent op already attached this same session, keep it - deleting it
      // would orphan a live debugger attach (stuck banner, teardown misses it).
      if (!session.isAttached) this.sessions.delete(tabId);
      throw e;
    }
    // Restriction-only recheck AFTER the attach protocol ran (SFX-3): a
    // decision that snapshotted cdpMode:true and was held open (e.g. by a
    // confirmation) can reach here AFTER a restricting policy push already
    // fired teardownAll below - nothing else would ever tear the JUST-MADE
    // session down, so handing it out registered would let the restriction
    // leak into a persistent debugger attach. Tear it down and refuse
    // instead; the in-flight decision simply fails this op (extra
    // restriction mid-flight is the fail-closed direction of decision 4),
    // and a blocked posture counts as no grant. The check runs after the
    // attach so the attach/registration interleaving stays synchronous for
    // the orphan-cleanup identity machinery above. An ERRORED policy read
    // fails closed exactly like a refusal (CS-2): the just-made attach must
    // not outlive a grant we could not read.
    let granted: boolean;
    try {
      const effective = await getEffectivePolicy();
      granted = effective.state !== "blocked" && effective.values.cdpMode === true;
    } catch (e) {
      await this.teardownIfCurrent(tabId, session);
      throw e;
    }
    if (!granted) {
      await this.teardownIfCurrent(tabId, session);
      throw new Error("cdp mode is not granted by the effective policy; refusing the session");
    }
    return session;
  }

  // Tear down only while the map still holds THIS session (SP-2):
  // browser.debugger.detach is tab-scoped, so a refusing call's teardown
  // resolving late must never rip down a newer session a concurrent call
  // attached to the same tab after ours was replaced.
  private async teardownIfCurrent(tabId: number, session: CdpSession): Promise<void> {
    if (this.sessions.get(tabId) === session) await this.teardown(tabId);
  }

  // Explicit teardown: detach and forget. Safe to call for an unknown tab.
  async teardown(tabId: number): Promise<void> {
    const session = this.sessions.get(tabId);
    if (!session) return;
    this.sessions.delete(tabId);
    await session.detach();
  }

  async teardownAll(): Promise<void> {
    const sessions = [...this.sessions.values()];
    this.sessions.clear();
    await Promise.all(sessions.map((s) => s.detach()));
  }

  // Chrome already detached us (onDetach) - drop the session WITHOUT issuing a
  // redundant detach command.
  handleExternalDetach(tabId: number): void {
    const session = this.sessions.get(tabId);
    if (!session) return;
    session.markDetached();
    this.sessions.delete(tabId);
  }

  // Whether a persistent session is currently held for this tab (no attach, no
  // side effect). Used by precise.ts to avoid a second, conflicting attach when
  // CDP mode already holds the tab.
  hasSession(tabId: number): boolean {
    return this.sessions.has(tabId);
  }

  // For diagnostics / tests.
  get size(): number {
    return this.sessions.size;
  }
}

export const cdpRegistry = new CdpSessionRegistry();

// Wire session teardown to the relevant Chrome events. Called once at SW
// startup from background.ts (NOT at module load, so importing the registry
// from unit tests / the backend selector stays free of chrome.* side effects).
let listenersInstalled = false;
export function installCdpLifecycleListeners(): void {
  if (listenersInstalled) return;
  listenersInstalled = true;

  // Tab closed → detach + forget.
  browser.tabs.onRemoved.addListener((tabId) => {
    void cdpRegistry.teardown(tabId);
  });

  // Chrome detached us (tab navigated to a non-debuggable page, user hit the
  // banner's "Cancel", DevTools opened, ...). Drop the session without re-detach.
  browser.debugger.onDetach.addListener((source) => {
    if (typeof source.tabId === "number") cdpRegistry.handleExternalDetach(source.tabId);
  });

  // cdpMode turned off -> detach everything so the banner goes away. The
  // effective mode is policy-resolved (ADR-0032 Phase 3): pre-cutover the
  // legacy stored value, post-cutover the host-pushed record - so an
  // accepted policy push restricting cdpMode tears live sessions down on
  // the push path (the push writes the policy storage keys). The legacy
  // "cdpMode" key stays in this trigger DELIBERATELY (Phase 5): the options
  // toggle that wrote it is gone, but the key can still change twice -
  // external storage tampering pre-cutover, and the post-cutover legacy
  // cleanup DELETING it (legacy-cleanup.ts), which fires this listener once.
  // Both firings are harmless by construction: the handler re-reads the
  // EFFECTIVE policy and only ever tears down (restriction-only), never
  // grants - so keeping the trigger is the simplest fail-closed reading.
  browser.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    const relevant = "cdpMode" in changes || POLICY_STORAGE_KEYS.some((key) => key in changes);
    if (!relevant) return;
    void (async () => {
      const effective = await getEffectivePolicy();
      // A blocked posture counts as no grant: teardown is restriction-only,
      // so it is always the safe reading of "not granted".
      const granted = effective.state !== "blocked" && effective.values.cdpMode === true;
      if (!granted) await cdpRegistry.teardownAll();
    })().catch((e) => {
      // Teardown is a restriction; a failed check must be loud, not silent.
      console.warn("[bb] cdp policy teardown check failed", e);
    });
  });
}
