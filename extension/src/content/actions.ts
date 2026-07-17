// Direct DOM actions: click, fill, text, screenshot, scroll.

import { getSetting } from "../shared/settings";
import type { OpArgs } from "../shared/types";
import { resolveTarget } from "./refs";
import { roleOf } from "./snapshot";
import { confirmAlways, confirmWithToast, describeAction, describeForToast } from "./toast";
import { truncate } from "./util";

export async function click(args: OpArgs) {
  const el = resolveTarget(args);
  const highRisk = isHighRiskClick(el);
  if (highRisk) {
    // The confirmation gate can be disabled by the user in settings. This is
    // dangerous (ADR-0006) but offered as an explicit opt-in.
    const confirmEnabled = await getSetting("confirmHighRiskClick");
    if (confirmEnabled !== false) {
      await confirmWithToast(`Click "${describeForToast(el)}"?`, describeAction(el, "click"));
    }
  }
  el.scrollIntoView({ block: "center" });
  el.focus?.();
  el.click();
  return { clicked: args.ref || args.selector, role: roleOf(el) };
}

function isHighRiskClick(el: HTMLElement) {
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

export async function fill(args: OpArgs) {
  const el = resolveTarget(args);
  const value = args.value ?? "";
  // Use the native setter path so frameworks (React, Vue) pick it up.
  await setNativeValue(el, value);
  return { filled: args.ref || args.selector };
}

// page_press — dispatch a synthetic keyboard event (keydown [+ keypress] +
// keyup) to the focused element. Confirmed on every press (a keypress can
// submit or trigger). Synthetic events are not trusted, so they will not fire a
// native default action such as submitting a form; that limitation is stated in
// the tool description.
export async function press(args: OpArgs) {
  const keys = (args.keys || "").trim();
  if (!keys) throw new Error("page_press needs `keys`");
  await confirmAlways(`Press "${keys}"?`, `press ${keys}`);
  const combo = parseCombo(keys);
  const el = (document.activeElement as HTMLElement) || document.body;
  dispatchKey(el, "keydown", combo);
  if (combo.key.length === 1) dispatchKey(el, "keypress", combo);
  dispatchKey(el, "keyup", combo);
  return { pressed: keys };
}

interface KeyCombo {
  key: string;
  code: string;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

// Parse "Control+A" / "Enter" / "a" into a KeyboardEvent-shaped combo. The last
// "+"-separated token is the key; the rest are modifiers.
export function parseCombo(spec: string): KeyCombo {
  const parts = spec.split("+").map((p) => p.trim());
  const key = parts.pop() || "";
  const mods = new Set(parts.map((p) => p.toLowerCase()));
  return {
    key,
    code: codeFor(key),
    ctrlKey: mods.has("control") || mods.has("ctrl"),
    shiftKey: mods.has("shift"),
    altKey: mods.has("alt") || mods.has("option"),
    metaKey: mods.has("meta") || mods.has("cmd") || mods.has("command"),
  };
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

function dispatchKey(el: HTMLElement, type: string, combo: KeyCombo) {
  el.dispatchEvent(
    new KeyboardEvent(type, {
      key: combo.key === "Space" ? " " : combo.key,
      code: combo.code,
      bubbles: true,
      cancelable: true,
      ctrlKey: combo.ctrlKey,
      shiftKey: combo.shiftKey,
      altKey: combo.altKey,
      metaKey: combo.metaKey,
    }),
  );
}

// page_hover — reveal hover menus / tooltips by dispatching pointer + mouse
// enter/over/move events. Low risk, no confirmation.
export async function hover(args: OpArgs) {
  const el = resolveTarget(args);
  el.scrollIntoView({ block: "center" });
  el.dispatchEvent(new PointerEvent("pointerover", { bubbles: true, cancelable: true }));
  el.dispatchEvent(new PointerEvent("pointerenter", { bubbles: false, cancelable: true }));
  el.dispatchEvent(new MouseEvent("mouseover", { bubbles: true, cancelable: true, view: window }));
  el.dispatchEvent(
    new MouseEvent("mouseenter", { bubbles: false, cancelable: true, view: window }),
  );
  el.dispatchEvent(new MouseEvent("mousemove", { bubbles: true, cancelable: true, view: window }));
  return { hovered: args.ref || args.selector, role: roleOf(el) };
}

// page_select — choose an option in a <select>. Confirmed (form state change).
export async function select(args: OpArgs) {
  const el = resolveTarget(args);
  if (el.tagName !== "SELECT") throw new Error("page_select target is not a <select>");
  const value = args.value ?? "";
  await confirmAlways(`Select "${value}"?`, `select ${value}`);
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
}

// Setting el.value directly doesn't trigger React/Vue change detection. Use the
// well-known trick of getting the native setter from the proto.
function setNativeValue(el: HTMLElement, value: string) {
  return new Promise<void>((resolve, reject) => {
    try {
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
      resolve();
    } catch (e) {
      reject(e);
    }
  });
}

export function text() {
  // Mask password fields.
  const cloneSrc = document.body.cloneNode(true) as HTMLElement;
  cloneSrc.querySelectorAll<HTMLInputElement>("input[type=password]").forEach((i) => {
    i.value = "••••••";
  });
  // Mask long digit runs that look like card numbers.
  const txt = (cloneSrc.innerText || "").replace(/\b\d{12,19}\b/g, "••••••");
  return { text: truncate(txt, 20000), url: location.href };
}

export async function screenshot() {
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

export function scroll(args: OpArgs) {
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
}
