// The app side of the shared language (ADR-0032 decision 7): apply the
// host's lang_current to the UI language, and record the user's own picks.
//
// The two directions are DIFFERENT paths on purpose, and the whole
// echo-loop rule lives in that split:
//
//  - APPLY (host -> app): an incoming lang-epoch notice (or startup) re-reads
//    langCurrent and applies it locally. This path NEVER calls langSet - an
//    apply that echoed a set back to the host would ping-pong with the
//    extension forever. Sequence-gated (decision 7): only a seq strictly
//    greater than the last applied one is applied, and seq === 0 (the host
//    store's never-explicitly-set default) is no signal at all - the user's
//    local preference stands.
//
//  - CHOOSE (app -> host): `chooseLanguage` is the ONE sanctioned call site
//    of api.langSet, and the LanguagePicker's click handler is its one
//    caller - a USER GESTURE, never a storage/apply/render path.

import { LANG_EPOCH_EVENT, onEpochEvent } from "@/lib/epoch-events";
import { setUiLanguage, type UiLanguage } from "@/lib/i18n";
import { api, type LangState } from "@/lib/tauri";

/** The highest host seq already applied (or minted by our own choose). */
let lastAppliedSeq = 0;

/** Whether a host value is one of the shared uiLanguage values. An
 * out-of-enum value is refused here (the host refuses them too; this is the
 * display-side backstop) and the current language stands. */
export function isSharedLanguage(value: string): value is UiLanguage {
  return value === "auto" || value === "en" || value === "zh_CN" || value === "zh_TW";
}

/** The APPLY path. Never emits: see the module docs. Returns whether the
 * state was applied (exported for the vitest suite, which pins the gating
 * and the never-emits rule). */
export function applyHostLanguage(state: LangState): boolean {
  if (state.seq === 0) return false; // never explicitly set anywhere: no signal
  if (state.seq <= lastAppliedSeq) return false; // stale or already applied
  if (!isSharedLanguage(state.value)) return false; // refuse, keep the current language
  lastAppliedSeq = state.seq;
  setUiLanguage(state.value);
  return true;
}

/** Re-read the host's language and apply it (the pull half of an epoch
 * notice, and the startup sync). An unreadable store keeps the local
 * preference - language carries no security weight, so there is nothing to
 * fail closed beyond not guessing. */
export async function syncLanguageFromHost(): Promise<void> {
  try {
    applyHostLanguage(await api.langCurrent());
  } catch {
    // Host unreadable/unavailable: the local preference stands.
  }
}

/** The CHOOSE path: a user gesture in the language picker. Applies locally
 * at once, then records the choice host-side so the extension follows.
 * Choices are SERIALIZED (a promise chain) so back-to-back clicks reach the
 * host in click order, and each response is fed back through the
 * non-emitting apply path: the response carries the host's resulting
 * `{ value, seq }`, so applying it both advances the cursor AND re-asserts
 * the host's truth - a stale concurrent read that overwrote the local
 * choice mid-flight gets corrected instead of being silently outlived by a
 * cursor that moved without its value. */
let chooseChain: Promise<void> = Promise.resolve();

export function chooseLanguage(lang: UiLanguage): void {
  setUiLanguage(lang);
  chooseChain = chooseChain
    .then(() => api.langSet(lang))
    .then(
      (state) => {
        // Guarded so the chain can never end up rejected: applyHostLanguage
        // notifies locale listeners (via setUiLanguage), and a throwing
        // listener would otherwise poison the chain and silently drop the
        // NEXT click's set. A failed re-assert only costs this response's
        // correction; the cursor and the host state stay consistent.
        try {
          applyHostLanguage(state);
        } catch {
          // A listener threw mid-apply: nothing to do here; the next
          // notice or choice re-converges.
        }
      },
      () => {
        // Host unavailable: the choice stays local-only (localStorage).
      },
    );
}

/** Startup wiring: one initial sync, then follow lang-epoch notices.
 * Returns the disposer. */
export function initLanguageSync(): () => void {
  void syncLanguageFromHost();
  return onEpochEvent(LANG_EPOCH_EVENT, () => void syncLanguageFromHost());
}

/** Test-only: reset the module cursor and the choice chain between cases. */
export function resetLanguageSyncForTests(): void {
  lastAppliedSeq = 0;
  chooseChain = Promise.resolve();
}
