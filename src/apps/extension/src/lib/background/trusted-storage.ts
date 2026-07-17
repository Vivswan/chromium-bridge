// #32: trust-state isolation. Everything security-relevant the extension
// persists - the enrollment pin, the pending pairing, the compromised marker,
// the requireEnrollment flag, the allowlist, every setting - lives in
// browser.storage.local, which Chrome exposes to CONTENT SCRIPTS by default.
// A compromised renderer, acting with a content script's privileges, could
// therefore read the trust state or, worse, WRITE it (plant a pin, clear a
// compromised marker, flip requireEnrollment off) and open the gate.
//
// The fix is an API-level access restriction, not a convention:
// setAccessLevel(TRUSTED_CONTEXTS) confines both storage areas to extension
// contexts (service worker, options/popup/confirm pages). Our content
// scripts read NOTHING from extension storage by design (everything they
// need arrives in the op message), so nothing legitimate is lost.
//
// Fail closed: the enrollment gate refuses ALL bridge traffic until the
// restriction is verifiably applied this SW life (readGateState awaits it
// first). If setAccessLevel is unavailable or throws - an older Chrome than
// the manifest's minimum_chrome_version should ever allow - the bridge stays
// blocked rather than running with renderer-readable trust state.
//
// RESIDUAL (named per zero-trust, not hidden): setAccessLevel is async and is
// applied AFTER the service worker starts, so it cannot lock storage at t=0.
// Between an SW cold-start and this call resolving there is a sub-millisecond
// window in which storage.local is still content-script-writable. Reaching it
// requires a content script from a PRIOR SW life (ours are runtime-injected
// only after the gate has already run once) whose renderer is compromised to
// call browser.storage.local.set, racing that window on the exact tick the SW
// respawns. Awaiting this result before every gate decision guarantees no
// value written AFTER it resolves is trusted, but a value tampered DURING the
// window would be locked in and then believed. No user-space API closes this
// (there is no synchronous storage lock); the enrollment ceremony's
// cryptographic checks bound - but do not erase - what a planted pin achieves.
// Recorded in the threat model and ADR-0027.

import { browser } from "wxt/browser";

export type Hardening = { ok: true } | { ok: false; reason: string };

let hardening: Promise<Hardening> | null = null;

/** Apply (once per SW life) and report the storage access restriction. */
export function hardenStorageAccess(): Promise<Hardening> {
  hardening ??= applyRestriction();
  return hardening;
}

async function applyRestriction(): Promise<Hardening> {
  try {
    // storage.local FIRST: it holds every trust-state value and is the only
    // area content-script-readable by default, so shrink its exposure before
    // anything else. storage.session already defaults to TRUSTED_CONTEXTS;
    // setting it is defense-in-depth (stated, not assumed) and must not delay
    // the local restriction.
    await browser.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    await browser.storage.session.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
    return { ok: true };
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    console.error("[bb] storage access hardening FAILED; bridge blocked:", reason);
    return { ok: false, reason };
  }
}

/** Tests only: forget the memoized result so a suite can drive both paths. */
export function resetStorageHardeningForTests(): void {
  hardening = null;
}
