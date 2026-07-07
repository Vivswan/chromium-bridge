// content.js — runs in each page (declared in manifest content_scripts).
//
// Receives { op, args } from background.js via chrome.runtime.onMessage and
// performs the actual DOM operation. Sends back a JSON-serializable result,
// or { __error: "..." } on failure.
//
// The snapshot builds an accessibility-style tree of *interactive* elements,
// each tagged with a stable `ref` (`data-zcb-ref="eN"`) that page_click /
// page_fill can target. This is the content-script approximation of a real
// a11y tree — see the project README for why we don't use chrome.debugger
// (the infobar) in v0.1.

(() => {
  if (window.__browserBridgeLoaded) return; // guard against double-inject
  window.__browserBridgeLoaded = true;

  const REF_ATTR = "data-zcb-ref";
  let refCounter = 0;
  // ref -> element, rebuilt on every snapshot. Stale refs (from a previous
  // snapshot whose element has since gone) resolve to null and the caller
  // gets a clear "ref not found, re-snapshot" error.
  let refMap = new Map();

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    handle(msg)
      .then((data) => sendResponse(data || {}))
      .catch((e) => sendResponse({ __error: String(e?.message || e) }));
    return true; // keep the channel open for the async response
  });

  async function handle(msg) {
    const { op, args } = msg;
    switch (op) {
      case "ping":
        return { pong: true };
      case "page_snapshot":
        return snapshot();
      case "page_click":
        return await click(args);
      case "page_fill":
        return await fill(args);
      case "page_text":
        return text();
      case "page_screenshot":
        return await screenshot();
      case "page_scroll":
        return scroll(args);
      case "page_wait_for":
        return await waitFor(args);
      default:
        throw new Error(`content: unknown op ${op}`);
    }
  }

  // ---- snapshot ----------------------------------------------------------

  function snapshot() {
    // Reset for a fresh, dense ref numbering each call.
    refCounter = 0;
    refMap = new Map();

    const out = [];
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_ELEMENT,
      { acceptNode: (el) => (isInteractive(el) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP) }
    );

    let el = walker.currentNode;
    // TreeWalker's first nextNode() walks from currentNode; start from root.
    while ((el = walker.nextNode())) {
      if (!isVisible(el)) continue;
      const ref = assignRef(el);
      out.push({
        ref,
        role: roleOf(el),
        name: nameOf(el),
        selector: cssSelectorOf(el),
        value: previewValue(el),
      });
    }
    return { refCount: out.length, nodes: out, url: location.href, title: document.title };
  }

  function assignRef(el) {
    // Reuse an existing ref if the element already has one from a prior
    // snapshot (keeps refs stable across calls when the page hasn't
    // changed).
    let ref = el.getAttribute(REF_ATTR);
    if (!ref) {
      refCounter += 1;
      ref = `e${refCounter}`;
      el.setAttribute(REF_ATTR, ref);
    }
    refMap.set(ref, el);
    return ref;
  }

  function isInteractive(el) {
    const tag = el.tagName.toLowerCase();
    if (INTERACTIVE_TAGS.has(tag)) return true;
    const role = el.getAttribute("role");
    if (role && INTERACTIVE_ROLES.has(role)) return true;
    if (el.hasAttribute("onclick")) return true;
    if (el.tabIndex >= 0) return true;
    return false;
  }

  const INTERACTIVE_TAGS = new Set([
    "a", "button", "input", "textarea", "select", "summary", "details",
    "label", "option", "optgroup",
  ]);
  const INTERACTIVE_ROLES = new Set([
    "button", "link", "checkbox", "radio", "textbox", "searchbox", "menuitem",
    "menuitemcheckbox", "menuitemradio", "tab", "combobox", "listbox",
    "option", "switch", "treeitem",
  ]);

  function roleOf(el) {
    const explicit = el.getAttribute("role");
    if (explicit) return explicit;
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (tag === "a" && el.hasAttribute("href")) return "link";
    if (tag === "button") return "button";
    if (tag === "input") {
      if (type === "checkbox") return "checkbox";
      if (type === "radio") return "radio";
      if (type === "submit" || type === "button" || type === "reset") return "button";
      return "textbox";
    }
    if (tag === "textarea") return "textbox";
    if (tag === "select") return "listbox";
    if (tag === "summary") return "button";
    return tag;
  }

  function nameOf(el) {
    // Simplified accessible-name computation (accname-1.2 subset).
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const parts = labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((n) => n.innerText || n.textContent || "")
        .join(" ")
        .trim();
      if (parts) return truncate(parts, 120);
    }
    const aria = el.getAttribute("aria-label");
    if (aria && aria.trim()) return truncate(aria.trim(), 120);
    // <label for> or wrapping <label>
    const labelFor = document.querySelector(`label[for="${el.id}"]`);
    if (labelFor) {
      const t = (labelFor.innerText || "").trim();
      if (t) return truncate(t, 120);
    }
    const wrapping = el.closest("label");
    if (wrapping && wrapping !== labelFor) {
      const t = (wrapping.innerText || "").trim();
      if (t) return truncate(t, 120);
    }
    if (el.title && el.title.trim()) return truncate(el.title.trim(), 120);
    // Fallbacks by content
    const txt = (el.innerText || el.textContent || "").trim();
    if (txt) return truncate(txt, 120);
    const placeholder = el.getAttribute("placeholder");
    if (placeholder) return truncate(placeholder, 120);
    const alt = el.getAttribute("alt");
    if (alt) return truncate(alt, 120);
    return "";
  }

  function previewValue(el) {
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") {
      const v = el.value || "";
      if (el.type === "password") return v ? "••••••" : "";
      return truncate(v, 60);
    }
    return undefined;
  }

  function truncate(s, n) {
    return s.length > n ? s.slice(0, n) + "…" : s;
  }

  function isVisible(el) {
    if (!el || !el.getClientRects) return false;
    const rects = el.getClientRects();
    if (rects.length === 0) return false;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    if (el.getAttribute("aria-hidden") === "true") return false;
    if (parseFloat(style.opacity) === 0) return false;
    return true;
  }

  // A cheap, *best-effort* CSS selector. Not guaranteed unique — the AI
  // should prefer `ref`. Used only as a fallback diagnostic.
  function cssSelectorOf(el) {
    const parts = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && cur !== document.body) {
      let part = cur.tagName.toLowerCase();
      if (cur.id) {
        part += `#${cur.id}`;
        parts.unshift(part);
        break;
      }
      const parent = cur.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter((c) => c.tagName === cur.tagName);
        if (siblings.length > 1) {
          const idx = siblings.indexOf(cur) + 1;
          part += `:nth-of-type(${idx})`;
        }
      }
      parts.unshift(part);
      cur = cur.parentElement;
    }
    return parts.join(" > ");
  }

  // ---- resolve ref or selector ------------------------------------------

  function resolveTarget(args) {
    if (args.ref) {
      // Prefer the live map from the most recent snapshot.
      let el = refMap.get(args.ref);
      if (!el) {
        // Fall back to a DOM query by attribute (covers SW-recycle cases
        // where the map was cleared but elements still carry the attr).
        el = document.querySelector(`[${REF_ATTR}="${args.ref}"]`);
        if (el) refMap.set(args.ref, el);
      }
      if (!el) throw new Error(`ref not found: ${args.ref} — call page_snapshot again`);
      return el;
    }
    if (args.selector) {
      const el = document.querySelector(args.selector);
      if (!el) throw new Error(`selector matched nothing: ${args.selector}`);
      return el;
    }
    throw new Error("click/fill needs `ref` or `selector`");
  }

  // ---- click -------------------------------------------------------------

  async function click(args) {
    const el = resolveTarget(args);
    const highRisk = isHighRiskClick(el);
    if (highRisk) {
      await confirmWithToast(`Click "${describeForToast(el)}"?`, describeAction(el, "click"));
    }
    el.scrollIntoView({ block: "center" });
    el.focus?.();
    el.click();
    return { clicked: args.ref || args.selector, role: roleOf(el) };
  }

  function isHighRiskClick(el) {
    // Submit buttons, and links that navigate, are gated.
    const role = roleOf(el);
    if (role === "button") {
      const type = (el.getAttribute("type") || "").toLowerCase();
      if (type === "submit") return true;
    }
    if (el.tagName === "A" && el.hasAttribute("href")) return true;
    if (role === "link") return true;
    return false;
  }

  // ---- fill --------------------------------------------------------------

  async function fill(args) {
    const el = resolveTarget(args);
    const value = args.__value ?? args.value ?? "";
    // Use the native setter path so frameworks (React, Vue) pick it up.
    await setNativeValue(el, value);
    return { filled: args.ref || args.selector };
  }

  // Setting el.value directly doesn't trigger React/Vue change detection.
  // Use the well-known trick of getting the native setter from the proto.
  function setNativeValue(el, value) {
    return new Promise((resolve, reject) => {
      try {
        el.focus?.();
        const proto =
          el.tagName === "TEXTAREA"
            ? HTMLTextAreaElement.prototype
            : el.tagName === "SELECT"
            ? HTMLSelectElement.prototype
            : HTMLInputElement.prototype;
        const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
        if (setter) {
          setter.call(el, value);
        } else {
          el.value = value;
        }
        el.dispatchEvent(new Event("input", { bubbles: true }));
        el.dispatchEvent(new Event("change", { bubbles: true }));
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  }

  // ---- text --------------------------------------------------------------

  function text() {
    // Mask password fields.
    const cloneSrc = document.body.cloneNode(true);
    cloneSrc.querySelectorAll("input[type=password]").forEach((i) => (i.value = "••••••"));
    // Mask long digit runs that look like card numbers.
    const txt = (cloneSrc.innerText || "").replace(/\b\d{12,19}\b/g, "••••••");
    return { text: truncate(txt, 20000), url: location.href };
  }

  // ---- screenshot --------------------------------------------------------

  async function screenshot() {
    // Content scripts can't take screenshots directly; ask background.
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ type: "capture_visible_tab" }, (resp) => {
        if (chrome.runtime.lastError || !resp || !resp.dataUrl) {
          reject(new Error(chrome.runtime.lastError?.message || "capture failed"));
        } else {
          resolve({ image: resp.dataUrl.split(",", 2)[1], mimeType: "image/png" });
        }
      });
    });
  }

  // ---- scroll ------------------------------------------------------------

  function scroll(args) {
    if (typeof args.pixels === "number") {
      window.scrollBy(0, args.pixels);
    } else if (args.direction) {
      const dh = window.innerHeight * 0.9;
      switch (args.direction) {
        case "down": window.scrollBy(0, dh); break;
        case "up": window.scrollBy(0, -dh); break;
        case "top": window.scrollTo(0, 0); break;
        case "bottom": window.scrollTo(0, document.body.scrollHeight); break;
      }
    } else {
      throw new Error("scroll needs `direction` or `pixels`");
    }
    return { scrollY: window.scrollY, scrollX: window.scrollX };
  }

  // ---- wait_for ----------------------------------------------------------

  function waitFor(args) {
    const timeoutMs = args.timeoutMs ?? 30000;
    const start = Date.now();
    return new Promise((resolve, reject) => {
      const tick = () => {
        if (args.selector) {
          if (document.querySelector(args.selector)) {
            return resolve({ matched: true, selector: args.selector });
          }
        }
        if (args.text) {
          if ((document.body.innerText || "").includes(args.text)) {
            return resolve({ matched: true, text: args.text });
          }
        }
        if (Date.now() - start > timeoutMs) {
          return reject(new Error(`wait_for timed out after ${timeoutMs}ms`));
        }
        setTimeout(tick, 150);
      };
      tick();
    });
  }

  // ---- Toast confirmation UI --------------------------------------------

  // Short-circuit window: a 60s window during which the same kind of
  // high-risk action on the same origin doesn't re-prompt.
  let lastConfirmed = { key: null, until: 0 };

  async function confirmWithToast(question, actionDesc) {
    const key = `${location.origin}:${actionDesc}`;
    if (lastConfirmed.key === key && Date.now() < lastConfirmed.until) {
      return; // within the grace window
    }
    const approved = await showToast(question);
    if (!approved) throw new Error(`user denied: ${actionDesc}`);
    lastConfirmed = { key, until: Date.now() + 60_000 };
  }

  function describeForToast(el) {
    return truncate(nameOf(el) || roleOf(el) || el.tagName.toLowerCase(), 40);
  }

  function describeAction(el, kind) {
    const role = roleOf(el);
    if (kind === "click") {
      if (role === "link" || el.tagName === "A") return "navigate";
      if (role === "button") return "submit";
      return "click";
    }
    return kind;
  }

  function showToast(question) {
    return new Promise((resolve) => {
      const host = ensureToastHost();
      const card = document.createElement("div");
      card.className = "zcb-toast-card";
      card.innerHTML = `
        <div class="zcb-toast-title">Browser Bridge</div>
        <div class="zcb-toast-q"></div>
        <div class="zcb-toast-actions">
          <button class="zcb-toast-deny">Deny</button>
          <button class="zcb-toast-allow">Allow</button>
        </div>`;
      card.querySelector(".zcb-toast-q").textContent = question;
      host.appendChild(card);

      let done = false;
      const finish = (val) => {
        if (done) return;
        done = true;
        card.classList.add("zcb-toast-out");
        setTimeout(() => card.remove(), 150);
        resolve(val);
      };
      card.querySelector(".zcb-toast-allow").onclick = () => finish(true);
      card.querySelector(".zcb-toast-deny").onclick = () => finish(false);
      // Auto-deny after 30s so the tool call doesn't hang forever.
      setTimeout(() => finish(false), 30000);
    });
  }

  function ensureToastHost() {
    let host = document.getElementById("__zcb_toast_host");
    if (!host) {
      host = document.createElement("div");
      host.id = "__zcb_toast_host";
      // Inline critical styles so it shows even if toast.css didn't load.
      host.style.cssText =
        "position:fixed;top:16px;right:16px;z-index:2147483647;" +
        "display:flex;flex-direction:column;gap:8px;pointer-events:none;";
      (document.body || document.documentElement).appendChild(host);
    }
    return host;
  }
})();
