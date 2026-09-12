// Everything security-relevant the extension persists (enrollment pin, pending pairing, compromised marker,
// policy state, allowlist, settings) lives in browser.storage.local, which Chrome exposes to CONTENT SCRIPTS
// by default, so a compromised renderer could read the trust state or plant a pin. setAccessLevel(TRUSTED_CONTEXTS)
// confines both storage areas to extension contexts at the API level; our content scripts read nothing from
// extension storage (everything they need arrives in the op message), so nothing legitimate is lost.
//
// Fail closed: enrollment.ts readGateState awaits this result before every gate decision, so an unavailable
// or throwing setAccessLevel (a Chrome older than the manifest's minimum_chrome_version) keeps the bridge blocked.
//
// Residual (ADR-0027 and the threat model): setAccessLevel is async, so between a service-worker cold start and
// this call resolving storage.local is briefly content-script-writable, and a value planted in that window is locked
// in and then believed. No user-space API closes it; the enrollment ceremony's cryptographic checks bound what a
// planted pin achieves.

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
    // storage.local FIRST: it holds every trust-state value and is the only area content-script-readable by
    // default. storage.session already defaults to TRUSTED_CONTEXTS; setting it too is defense in depth.
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
