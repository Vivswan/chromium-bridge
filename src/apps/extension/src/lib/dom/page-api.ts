// THE page-side DOM implementation, shared by both page backends.
//
// createPageApi is ONE self-contained function: no imports and no references
// to module scope (helpers are declared inside it). That property is what
// lets the CDP backend ship it whole - Function.prototype.toString() the
// factory, evaluate `(factory)(refAttr).method(args)` in the page's MAIN
// world - while the content script simply calls createPageApi(REF_ATTR) once
// and keeps the instance. One source replaces the old hand-ported mirrors
// (content/{snapshot,refs,actions,wait,storage}.ts vs cdp/page-fns.ts), so
// the two backends can no longer drift apart. Self-containment is enforced
// by a test that rebuilds the factory from its own source text.
//
// Behavior notes:
// - Refs: elements are tagged with the `refAttr` attribute ("e1", "e2", ...).
//   The instance keeps a ref -> element map (fast path, survives within one
//   content-script life); a stale map falls back to a DOM query by attribute,
//   which is also what makes refs work statelessly in CDP mode where every
//   call evaluates a fresh instance.
// - No confirmations and no settings reads happen here: risk classification,
//   user confirmation, and egress masking are the service worker's job
//   (lib/background/confirm + egress). The page only probes and acts.
// - readStorage returns RAW values; the SW masks them before egress.

export const REF_ATTR = "data-zcb-ref";

export interface PageApi {
  snapshot(): SnapshotResult;
  text(): { text: string; url: string };
  scroll(args: { pixels?: number; direction?: string }): { scrollY: number; scrollX: number };
  waitFor(args: {
    nav?: boolean;
    selector?: string;
    text?: string;
    timeoutMs?: number;
  }): Promise<unknown>;
  readStorage(args: { type?: string; key?: string }): StorageReadResult;
  probeClick(args: TargetArgs): ClickProbe;
  /** When `expect` is set (the probe the user approved), the target is
   * re-probed immediately before the click and the click is REFUSED if the
   * descriptor changed - a page cannot swap the target behind an open
   * confirmation. */
  click(args: TargetArgs & { expect?: ClickProbe }): {
    clicked: string | undefined;
    role: string;
  };
  fill(args: TargetArgs & { value?: string }): { filled: string | undefined };
  press(args: { keys: string }): { pressed: string };
  hover(args: TargetArgs): { hovered: string | undefined; role: string };
  select(args: TargetArgs & { value?: string }): { selected: string; text: string };
}

export interface TargetArgs {
  ref?: string;
  selector?: string;
}

export interface SnapshotNode {
  ref: string;
  role: string;
  name: string;
  selector: string;
  value: string | undefined;
}

export interface SnapshotResult {
  refCount: number;
  nodes: SnapshotNode[];
  url: string;
  title: string;
}

/** What the SW needs to classify a click's risk without owning the DOM. */
export interface ClickProbe {
  tagName: string; // uppercase, as the DOM reports it
  role: string;
  type: string; // lowercased input type, "" if none
  hasHref: boolean;
  name: string;
}

export type StorageReadResult =
  | { key: string; found: false }
  | { key: string; found: true; value: string }
  | {
      type: string;
      entries: Record<string, string>;
      count: number;
      truncated: boolean;
      totalKeys: number;
    };

export function createPageApi(refAttr: string): PageApi {
  // ---- shared helpers (all closure-local; nothing from module scope) ------

  function truncate(s: string, n: number): string {
    return s.length > n ? `${s.slice(0, n)}...` : s;
  }

  const INTERACTIVE_TAGS = new Set([
    "a",
    "button",
    "input",
    "textarea",
    "select",
    "summary",
    "details",
    "label",
    "option",
    "optgroup",
  ]);
  const INTERACTIVE_ROLES = new Set([
    "button",
    "link",
    "checkbox",
    "radio",
    "textbox",
    "searchbox",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "tab",
    "combobox",
    "listbox",
    "option",
    "switch",
    "treeitem",
  ]);

  function isInteractive(el: HTMLElement): boolean {
    const tag = el.tagName.toLowerCase();
    if (INTERACTIVE_TAGS.has(tag)) return true;
    const role = el.getAttribute("role");
    if (role && INTERACTIVE_ROLES.has(role)) return true;
    if (el.hasAttribute("onclick")) return true;
    if (el.tabIndex >= 0) return true;
    return false;
  }

  function roleOf(el: HTMLElement): string {
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

  // Simplified accessible-name computation (accname-1.2 subset).
  function nameOf(el: HTMLElement): string {
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const parts = labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter((n): n is HTMLElement => n !== null)
        .map((n) => n.innerText || n.textContent || "")
        .join(" ")
        .trim();
      if (parts) return truncate(parts, 120);
    }
    const aria = el.getAttribute("aria-label");
    if (aria?.trim()) return truncate(aria.trim(), 120);
    const labelFor = el.id ? document.querySelector<HTMLElement>(`label[for="${el.id}"]`) : null;
    if (labelFor) {
      const t = (labelFor.innerText || "").trim();
      if (t) return truncate(t, 120);
    }
    const wrapping = el.closest("label");
    if (wrapping && wrapping !== labelFor) {
      const t = (wrapping.innerText || "").trim();
      if (t) return truncate(t, 120);
    }
    if (el.title?.trim()) return truncate(el.title.trim(), 120);
    const txt = (el.innerText || el.textContent || "").trim();
    if (txt) return truncate(txt, 120);
    const placeholder = el.getAttribute("placeholder");
    if (placeholder) return truncate(placeholder, 120);
    const alt = el.getAttribute("alt");
    if (alt) return truncate(alt, 120);
    return "";
  }

  function previewValue(el: HTMLElement): string | undefined {
    if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT") {
      const field = el as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
      const v = field.value || "";
      if (field.type === "password") return v ? "••••••" : "";
      return truncate(v, 60);
    }
    return undefined;
  }

  function isVisible(el: HTMLElement): boolean {
    if (!el?.getClientRects) return false;
    const rects = el.getClientRects();
    if (rects.length === 0) return false;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    if (Number.parseFloat(style.opacity) === 0) return false;
    // aria-hidden hides the element AND its entire subtree; walk up to catch
    // a visibly-styled element inside a hidden ancestor.
    let cur: HTMLElement | null = el;
    while (cur && cur.nodeType === 1) {
      if (cur.getAttribute("aria-hidden") === "true") return false;
      cur = cur.parentElement;
    }
    return true;
  }

  // A cheap, best-effort CSS selector. Not guaranteed unique - callers should
  // prefer `ref`. Used only as a fallback diagnostic.
  function cssSelectorOf(el: HTMLElement): string {
    const parts: string[] = [];
    let cur: HTMLElement | null = el;
    while (cur && cur.nodeType === 1 && cur !== document.body) {
      let part = cur.tagName.toLowerCase();
      if (cur.id) {
        part += `#${cur.id}`;
        parts.unshift(part);
        break;
      }
      const parent = cur.parentElement;
      if (parent) {
        const tag = cur.tagName;
        const siblings = Array.from(parent.children).filter((c: Element) => c.tagName === tag);
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

  // ---- refs ----------------------------------------------------------------

  // ref -> element, rebuilt on every snapshot. In the content script the
  // instance (and this map) lives as long as the injected script; in CDP mode
  // every call gets a fresh instance, so resolution rides on the attribute
  // fallback below - both paths tag the SAME attribute, so refs interoperate.
  let refCounter = 0;
  let refMap = new Map<string, HTMLElement>();

  // Reuse an element's existing ref attribute (stable across snapshots) and
  // advance past reused numbers so freshly-inserted elements never collide
  // with them (the SPA re-snapshot case).
  function assignRef(el: HTMLElement): string {
    let ref = el.getAttribute(refAttr);
    if (ref) {
      const reused = Number.parseInt(ref.slice(1), 10);
      if (!Number.isNaN(reused) && reused > refCounter) refCounter = reused;
    } else {
      refCounter += 1;
      ref = `e${refCounter}`;
      el.setAttribute(refAttr, ref);
    }
    refMap.set(ref, el);
    return ref;
  }

  function resolveTarget(args: { ref?: string; selector?: string }): HTMLElement {
    if (args.ref) {
      // Prefer the live map from the most recent snapshot; fall back to a DOM
      // query by attribute (fresh instance, or SW recycle re-injection).
      let el = refMap.get(args.ref);
      if (!el) {
        el = document.querySelector<HTMLElement>(`[${refAttr}="${args.ref}"]`) ?? undefined;
        if (el) refMap.set(args.ref, el);
      }
      if (!el) throw new Error(`ref not found: ${args.ref} - call page_snapshot again`);
      return el;
    }
    if (args.selector) {
      const el = document.querySelector<HTMLElement>(args.selector);
      if (!el) throw new Error(`selector matched nothing: ${args.selector}`);
      return el;
    }
    throw new Error("this action needs `ref` or `selector`");
  }

  function probeOf(el: HTMLElement): ClickProbe {
    return {
      tagName: el.tagName,
      role: roleOf(el),
      type: (el.getAttribute("type") || "").toLowerCase(),
      hasHref: el.tagName === "A" && el.hasAttribute("href"),
      name: nameOf(el),
    };
  }

  function setNativeValue(el: HTMLElement, value: string): void {
    // Setting el.value directly doesn't trigger React/Vue change detection;
    // use the native setter from the prototype.
    el.focus?.();
    const field = el as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;
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
      field.value = value;
    }
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Best-effort KeyboardEvent.code for a key name (enough for common handlers).
  function codeFor(key: string): string {
    if (key.length === 1) {
      if (/[a-zA-Z]/.test(key)) return `Key${key.toUpperCase()}`;
      if (/[0-9]/.test(key)) return `Digit${key}`;
      if (key === " ") return "Space";
    }
    const named: Record<string, string> = {
      Enter: "Enter",
      Escape: "Escape",
      Esc: "Escape",
      Tab: "Tab",
      Backspace: "Backspace",
      Delete: "Delete",
      ArrowUp: "ArrowUp",
      ArrowDown: "ArrowDown",
      ArrowLeft: "ArrowLeft",
      ArrowRight: "ArrowRight",
      Home: "Home",
      End: "End",
      PageUp: "PageUp",
      PageDown: "PageDown",
      Space: "Space",
    };
    return named[key] || "";
  }

  // ---- the api ---------------------------------------------------------------

  return {
    snapshot() {
      // Fresh, dense numbering per snapshot (existing attributes are reused).
      refCounter = 0;
      refMap = new Map();
      const out: SnapshotNode[] = [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_ELEMENT, {
        acceptNode: (el) =>
          isInteractive(el as HTMLElement) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP,
      });
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        const el = node as HTMLElement; // SHOW_ELEMENT guarantees an element
        if (!isVisible(el)) continue;
        out.push({
          ref: assignRef(el),
          role: roleOf(el),
          name: nameOf(el),
          selector: cssSelectorOf(el),
          value: previewValue(el),
        });
      }
      return { refCount: out.length, nodes: out, url: location.href, title: document.title };
    },

    text() {
      // Mask password fields and card-number-like digit runs in the page copy.
      const cloneSrc = document.body.cloneNode(true) as HTMLElement;
      for (const i of Array.from(
        cloneSrc.querySelectorAll<HTMLInputElement>("input[type=password]"),
      )) {
        i.value = "••••••";
      }
      const txt = (cloneSrc.innerText || "").replace(/\b\d{12,19}\b/g, "••••••");
      return { text: truncate(txt, 20000), url: location.href };
    },

    scroll(args) {
      if (typeof args.pixels === "number") {
        window.scrollBy(0, args.pixels);
      } else if (args.direction) {
        const dh = window.innerHeight * 0.9;
        switch (args.direction) {
          case "down":
            window.scrollBy(0, dh);
            break;
          case "up":
            window.scrollBy(0, -dh);
            break;
          case "top":
            window.scrollTo(0, 0);
            break;
          case "bottom":
            window.scrollTo(0, document.body.scrollHeight);
            break;
        }
      } else {
        throw new Error("scroll needs `direction` or `pixels`");
      }
      return { scrollY: window.scrollY, scrollX: window.scrollX };
    },

    waitFor(args) {
      const timeoutMs = args.timeoutMs ?? 30000;
      const start = Date.now();
      return new Promise((resolve, reject) => {
        let done = false;
        const onLoad = () => {
          if (args.nav) {
            finish(resolve, {
              matched: true,
              nav: true,
              url: location.href,
              readyState: document.readyState,
            });
          }
        };
        const finish = (fn: (v: unknown) => void, value: unknown) => {
          if (done) return;
          done = true;
          window.removeEventListener("load", onLoad, true);
          fn(value);
        };
        if (args.nav) {
          if (document.readyState === "complete") {
            return finish(resolve, {
              matched: true,
              nav: true,
              url: location.href,
              readyState: document.readyState,
            });
          }
          window.addEventListener("load", onLoad, true);
        }
        const tick = () => {
          if (done) return;
          if (args.selector) {
            if (document.querySelector(args.selector)) {
              return finish(resolve, { matched: true, selector: args.selector });
            }
          }
          if (args.text) {
            if ((document.body.innerText || "").includes(args.text)) {
              return finish(resolve, { matched: true, text: args.text });
            }
          }
          if (Date.now() - start > timeoutMs) {
            return finish(reject, new Error(`wait_for timed out after ${timeoutMs}ms`));
          }
          setTimeout(tick, 150);
        };
        tick();
      });
    },

    readStorage(args) {
      // RAW values on purpose: the SW masks them before egress (always-on for
      // storage_get, independent of the eval mask toggle - ADR-0010).
      const type = args.type === "session" ? "session" : "local";
      const key = args.key;
      let store: Storage;
      try {
        store = type === "session" ? window.sessionStorage : window.localStorage;
      } catch (e) {
        throw new Error(`storage unavailable: ${e instanceof Error ? e.message : String(e)}`, {
          cause: e,
        });
      }
      if (key !== undefined && key !== null && key !== "") {
        const raw = store.getItem(key);
        if (raw === null) return { key, found: false };
        return { key, found: true, value: raw };
      }
      const entries: Record<string, string> = {};
      let count = 0;
      const MAX = 500;
      for (let i = 0; i < store.length && count < MAX; i++) {
        const k = store.key(i);
        if (k === null) continue;
        try {
          entries[k] = store.getItem(k) || "";
        } catch {
          entries[k] = "[unreadable]";
        }
        count++;
      }
      const truncated = store.length > MAX;
      return { type, entries, count, truncated, totalKeys: store.length };
    },

    probeClick(args) {
      const el = resolveTarget(args);
      return probeOf(el);
    },

    click(args) {
      const el = resolveTarget(args);
      el.scrollIntoView({ block: "center" });
      el.focus?.();
      if (args.expect) {
        // Bind the act to the approval: the user approved a specific
        // descriptor (confirm/gate.ts); if the element no longer matches it,
        // the page changed the target while the confirmation was open -
        // refuse. Checked AFTER scroll/focus (whose handlers a hostile page
        // controls and could use to mutate the target) so nothing scriptable
        // runs between this comparison and the click itself.
        const now = probeOf(el);
        const same =
          now.tagName === args.expect.tagName &&
          now.role === args.expect.role &&
          now.type === args.expect.type &&
          now.hasHref === args.expect.hasHref &&
          now.name === args.expect.name;
        if (!same) {
          throw new Error(
            "click target changed while the confirmation was open - call page_snapshot again",
          );
        }
      }
      el.click();
      return { clicked: args.ref || args.selector, role: roleOf(el) };
    },

    fill(args) {
      const el = resolveTarget(args);
      setNativeValue(el, args.value ?? "");
      return { filled: args.ref || args.selector };
    },

    press(args) {
      const spec = (args.keys || "").trim();
      if (!spec) throw new Error("page_press needs `keys`");
      // Parse "Control+A" / "Enter" / "a": the last "+"-separated token is
      // the key; the rest are modifiers.
      const parts = spec.split("+").map((p) => p.trim());
      const key = parts.pop() || "";
      const mods = new Set(parts.map((p) => p.toLowerCase()));
      const combo = {
        key: key === "Space" ? " " : key,
        code: codeFor(key),
        ctrlKey: mods.has("control") || mods.has("ctrl"),
        shiftKey: mods.has("shift"),
        altKey: mods.has("alt") || mods.has("option"),
        metaKey: mods.has("meta") || mods.has("cmd") || mods.has("command"),
      };
      const el = (document.activeElement as HTMLElement) || document.body;
      const dispatch = (type: string) =>
        el.dispatchEvent(
          new KeyboardEvent(type, {
            key: combo.key,
            code: combo.code,
            bubbles: true,
            cancelable: true,
            ctrlKey: combo.ctrlKey,
            shiftKey: combo.shiftKey,
            altKey: combo.altKey,
            metaKey: combo.metaKey,
          }),
        );
      dispatch("keydown");
      if (combo.key.length === 1) dispatch("keypress");
      dispatch("keyup");
      return { pressed: spec };
    },

    hover(args) {
      const el = resolveTarget(args);
      el.scrollIntoView({ block: "center" });
      el.dispatchEvent(new PointerEvent("pointerover", { bubbles: true, cancelable: true }));
      el.dispatchEvent(new PointerEvent("pointerenter", { bubbles: false, cancelable: true }));
      el.dispatchEvent(
        new MouseEvent("mouseover", { bubbles: true, cancelable: true, view: window }),
      );
      el.dispatchEvent(
        new MouseEvent("mouseenter", { bubbles: false, cancelable: true, view: window }),
      );
      el.dispatchEvent(
        new MouseEvent("mousemove", { bubbles: true, cancelable: true, view: window }),
      );
      return { hovered: args.ref || args.selector, role: roleOf(el) };
    },

    select(args) {
      const el = resolveTarget(args);
      if (el.tagName !== "SELECT") throw new Error("page_select target is not a <select>");
      const value = args.value ?? "";
      const sel = el as HTMLSelectElement;
      const opts = Array.from(sel.options);
      let idx = opts.findIndex((o) => o.value === value);
      if (idx < 0) idx = opts.findIndex((o) => (o.textContent || "").trim() === value);
      const opt = opts[idx];
      if (!opt) throw new Error(`page_select: no option matching "${value}"`);
      sel.selectedIndex = idx;
      sel.dispatchEvent(new Event("input", { bubbles: true }));
      sel.dispatchEvent(new Event("change", { bubbles: true }));
      return { selected: opt.value, text: (opt.textContent || "").trim() };
    },
  };
}
