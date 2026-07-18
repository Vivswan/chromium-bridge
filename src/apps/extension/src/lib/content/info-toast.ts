// The informational (non-gating) in-page notice. This is NOT a confirmation
// surface: it defaults to PROCEED after its timeout, and the user can only
// cancel. Real confirmations moved OFF the page-reachable DOM to the
// extension-owned window (ADR-0027); this notice stays in-page because a page
// suppressing its own courtesy warning gains nothing (it cannot approve
// anything here), while a focus-stealing window for a heads-up would be
// hostile UX. Styles are inline so no stylesheet injection is needed; the
// colors come from the Control Tower constants (theme-colors.ts) and follow
// the OS scheme, since our stylesheet's tokens are not injected here.
//
// Layout follows the Control Tower toast: mono brand line, message, and a
// draining countdown track next to a quiet Cancel. The track fill is neutral
// ink on purpose - a countdown is information, and the signal colors stay
// reserved for live/pending/danger.

import { TOAST_DARK, TOAST_LIGHT, type ToastPalette } from "../shared/theme-colors";

const TOAST_MS = 8000;
const MONO = 'ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace';

function toastPalette(): ToastPalette {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? TOAST_DARK : TOAST_LIGHT;
}

export function showInfoToast(message: string, cancelLabel?: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = ensureToastHost();
    const p = toastPalette();
    const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;
    const card = document.createElement("div");
    // Announced to screen readers when appended (the notice auto-proceeds,
    // so a silent injection would skip the one chance to cancel).
    card.setAttribute("role", "status");
    card.style.cssText =
      `box-sizing:border-box;pointer-events:auto;background:${p.surface};color:${p.text};` +
      `border:1px solid ${p.edgeStrong};border-radius:10px;padding:11px 12px 12px;width:316px;` +
      "font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;font-size:12px;line-height:1.45;";
    const head = document.createElement("div");
    head.style.cssText = "display:flex;align-items:center;gap:7px;margin-bottom:5px;";
    const title = document.createElement("div");
    title.textContent = "CHROMIUM BRIDGE";
    title.style.cssText = `font-family:${MONO};font-size:10px;letter-spacing:0.08em;color:${p.textSecondary};`;
    head.appendChild(title);
    const text = document.createElement("div");
    text.textContent = message;
    text.style.cssText = `word-break:break-word;color:${p.text};`;
    const foot = document.createElement("div");
    foot.style.cssText = "display:flex;align-items:center;gap:9px;margin-top:9px;";
    const track = document.createElement("div");
    track.style.cssText = `flex:1;height:2px;border-radius:1px;background:${p.control};overflow:hidden;`;
    const fill = document.createElement("div");
    fill.style.cssText = `width:100%;height:100%;background:${p.textSecondary};transform-origin:left;`;
    track.appendChild(fill);
    const cancel = document.createElement("button");
    // Localized by the SW caller (the content script reads no extension
    // storage, so it cannot resolve the user's chosen locale itself).
    cancel.textContent = cancelLabel || "Cancel";
    cancel.style.cssText =
      `padding:3px 9px;border-radius:6px;border:1px solid transparent;color:${p.textSecondary};` +
      "background:transparent;cursor:pointer;font-size:11px;font-weight:600;font-family:inherit;";
    cancel.onmouseenter = () => {
      cancel.style.background = p.control;
      cancel.style.color = p.text;
    };
    cancel.onmouseleave = () => {
      cancel.style.background = "transparent";
      cancel.style.color = p.textSecondary;
    };
    foot.appendChild(track);
    foot.appendChild(cancel);
    card.appendChild(head);
    card.appendChild(text);
    card.appendChild(foot);
    host.appendChild(card);

    // Entrance: transform/opacity only, ease-out; skipped under reduced motion.
    if (!reduceMotion) {
      card.animate(
        [
          { opacity: 0, transform: "translateY(8px)" },
          { opacity: 1, transform: "translateY(0)" },
        ],
        { duration: 200, easing: "cubic-bezier(0.23, 1, 0.32, 1)" },
      );
    }

    // Drain the countdown track (transform only). The drain is information,
    // not decoration, so reduced motion STEPS it (one discrete move per
    // second) instead of skipping it - a permanently full bar would claim
    // "all time remaining" while the auto-proceed timer runs.
    fill.animate([{ transform: "scaleX(1)" }, { transform: "scaleX(0)" }], {
      duration: TOAST_MS,
      easing: reduceMotion ? "steps(8, jump-none)" : "linear",
      fill: "forwards",
    });

    let done = false;
    const finish = (proceed: boolean) => {
      if (done) return;
      done = true;
      if (reduceMotion) {
        card.remove();
      } else {
        // Exit: quick fade, faster than the entrance.
        const out = card.animate([{ opacity: 1 }, { opacity: 0 }], {
          duration: 120,
          easing: "ease-out",
        });
        out.onfinish = () => card.remove();
      }
      resolve(proceed);
    };
    cancel.onclick = () => finish(false);
    // Auto-proceed after the timeout (informational, not a confirmation gate).
    setTimeout(() => finish(true), TOAST_MS);
  });
}

function ensureToastHost(): HTMLElement {
  let host = document.getElementById("__zcb_toast_host");
  if (!host) {
    host = document.createElement("div");
    host.id = "__zcb_toast_host";
    host.style.cssText =
      "position:fixed;bottom:16px;right:16px;z-index:2147483647;" +
      "display:flex;flex-direction:column;gap:8px;pointer-events:none;";
    (document.body || document.documentElement).appendChild(host);
  }
  return host;
}
