// The informational (non-gating) in-page notice. This is NOT a confirmation
// surface: it defaults to PROCEED after its timeout, and the user can only
// cancel. Real confirmations moved OFF the page-reachable DOM to the
// extension-owned window (ADR-0027); this notice stays in-page because a page
// suppressing its own courtesy warning gains nothing (it cannot approve
// anything here), while a focus-stealing window for a heads-up would be
// hostile UX. Styles are inline so no stylesheet injection is needed.

export function showInfoToast(message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const host = ensureToastHost();
    const card = document.createElement("div");
    card.style.cssText =
      "box-sizing:border-box;pointer-events:auto;background:#f0f7ff;color:#1f2937;" +
      "border:1.5px solid #2563eb;border-left:4px solid #2563eb;border-radius:12px;" +
      "box-shadow:0 10px 30px rgba(0,0,0,.16);padding:14px 16px;width:360px;" +
      "font-family:-apple-system,system-ui,sans-serif;font-size:13px;line-height:1.5;";
    const title = document.createElement("div");
    title.textContent = "Chromium Bridge";
    title.style.cssText = "font-weight:700;margin-bottom:6px;color:#1d4ed8;";
    const text = document.createElement("div");
    text.textContent = message;
    text.style.cssText = "margin-bottom:12px;word-break:break-word;color:#374151;";
    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;gap:8px;justify-content:flex-end;";
    const cancel = document.createElement("button");
    cancel.textContent = "Cancel";
    cancel.style.cssText =
      "padding:6px 14px;border-radius:8px;border:1px solid #d1d5db;color:#374151;" +
      "background:#fff;cursor:pointer;font-size:12px;font-weight:600;";
    actions.appendChild(cancel);
    card.appendChild(title);
    card.appendChild(text);
    card.appendChild(actions);
    host.appendChild(card);

    let done = false;
    const finish = (proceed: boolean) => {
      if (done) return;
      done = true;
      card.remove();
      resolve(proceed);
    };
    cancel.onclick = () => finish(false);
    // Auto-proceed after 8s (informational, not a confirmation gate).
    setTimeout(() => finish(true), 8000);
  });
}

function ensureToastHost(): HTMLElement {
  let host = document.getElementById("__zcb_toast_host");
  if (!host) {
    host = document.createElement("div");
    host.id = "__zcb_toast_host";
    host.style.cssText =
      "position:fixed;top:16px;right:16px;z-index:2147483647;" +
      "display:flex;flex-direction:column;gap:8px;pointer-events:none;";
    (document.body || document.documentElement).appendChild(host);
  }
  return host;
}
