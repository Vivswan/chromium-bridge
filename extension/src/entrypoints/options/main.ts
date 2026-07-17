// options.ts — the extension's options page. Reads/writes browser.storage.local.
//
// All settings live in browser.storage.local as flat keys. DEFAULTS is the single
// source of truth in shared/settings.ts — background/content/options all import
// it; add a new setting there (and to the Settings type), not in three places.

import { salvageSettings, TOOLS } from "@chromium-bridge/shared";
import { browser } from "wxt/browser";
import { DEFAULTS } from "@/lib/shared/settings";
import type { Settings } from "@/lib/shared/types";

// Elements are declared in options.html; `$` asserts presence (the page owns
// its own DOM). Pass a subtype when you need element-specific fields.
function $<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

// ---- load / save settings -------------------------------------------------

async function loadSettings(): Promise<Settings> {
  const keys = Object.keys(DEFAULTS);
  const stored = await browser.storage.local.get(keys);
  // Field-by-field salvage: a stored value that fails its schema falls back
  // to that field's default instead of being rendered as-is.
  return salvageSettings(stored);
}

async function saveSetting(key: string, value: unknown) {
  await browser.storage.local.set({ [key]: value });
  flashToast("已保存");
}

// ---- toast feedback -------------------------------------------------------

let toastTimer: ReturnType<typeof setTimeout> | null = null;
function flashToast(msg: string) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.add("show");
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove("show"), 1200);
}

// ---- render: boolean cards ------------------------------------------------

function renderBool(key: string) {
  const input = $(key);
  const warn = $(`${key}-warn`);
  const card = $(`card-${key}`);
  input.addEventListener("change", (e: Event) => {
    const checked = (e.target as HTMLInputElement).checked;
    if (warn) warn.style.display = checked ? "none" : "block";
    if (card) card.classList.toggle("danger", !!warn && !checked);
    void saveSetting(key, checked);
  });
}

// The "allow all sites" toggle is special: enabling it MUST also grant the
// <all_urls> optional host permission (via a user-gesture permissions.request),
// otherwise content-script injection silently fails on non-allowlisted origins.
// If the user declines the permission prompt, roll the checkbox back to off.
function wireAllowAllSites() {
  const input = $("allowAllSites");
  const warn = $("allowAllSites-warn");
  const card = $("card-allowAllSites");
  input.addEventListener("change", async (e: Event) => {
    const target = e.target as HTMLInputElement;
    const checked = target.checked;
    if (checked) {
      // Request the all-urls host permission. This must happen inside the
      // change handler (a user-gesture context) — MV3 forbids requesting
      // permissions from arbitrary async code.
      const granted = await browser.permissions.request({
        origins: ["<all_urls>"],
      });
      if (!granted) {
        // User declined the OS prompt → roll back.
        target.checked = false;
        flashToast("未授权 <所有网址>,已保持逐站点审批");
        return;
      }
    } else {
      // Turning off: release the host permission too.
      await browser.permissions.remove({ origins: ["<all_urls>"] });
    }
    if (warn) warn.style.display = checked ? "block" : "none";
    if (card) card.classList.toggle("danger", checked);
    await saveSetting("allowAllSites", checked);
    flashToast(checked ? "已允许所有站点" : "已恢复逐站点审批");
  });
}

// ---- render: number fields ------------------------------------------------

function renderNumber(key: string) {
  const input = $(key);
  input.addEventListener("change", (e: Event) => {
    const v = parseInt((e.target as HTMLInputElement).value, 10);
    if (Number.isNaN(v)) return;
    void saveSetting(key, v);
  });
}

// ---- render: tools grid ---------------------------------------------------

function renderToolsGrid(disabledTools: string[]) {
  const grid = $("tools-grid");
  const disabled = new Set(Array.isArray(disabledTools) ? disabledTools : []);
  grid.innerHTML = TOOLS.map((t) => {
    const checked = disabled.has(t.op) ? "" : "checked";
    return (
      `<label class="tool">` +
      `<input type="checkbox" data-op="${escapeAttr(t.op)}" ${checked} />` +
      `<div><div class="name">${escapeHtml(t.op)}</div>` +
      `<div class="tdesc">${escapeHtml(t.desc)}</div></div>` +
      `</label>`
    );
  }).join("");
  grid.querySelectorAll<HTMLInputElement>("input[type=checkbox]").forEach((cb) => {
    cb.addEventListener("change", async () => {
      const all = grid.querySelectorAll<HTMLInputElement>("input[type=checkbox]");
      const next: string[] = [];
      all.forEach((c) => {
        if (!c.checked) next.push(c.getAttribute("data-op")!);
      });
      await saveSetting("disabledTools", next);
    });
  });
}

// ---- render: allowlist ----------------------------------------------------

async function refreshAllowlist() {
  const resp = await send({ type: "get_allowlist" });
  const list = (resp?.list as string[]) || [];
  const box = $("site-list");
  if (list.length === 0) {
    box.innerHTML = `<div class="empty">还没有允许任何站点。</div>`;
    return;
  }
  box.innerHTML = list
    .map(
      (g) =>
        `<div class="item"><code>${escapeHtml(g)}</code>` +
        `<button class="danger" data-glob="${escapeAttr(g)}">移除</button></div>`,
    )
    .join("");
  box.querySelectorAll<HTMLButtonElement>("button").forEach((b) => {
    b.onclick = async () => {
      const glob = b.getAttribute("data-glob")!;
      await send({ type: "remove_allow", glob });
      await refreshAllowlist();
      flashToast("已移除");
    };
  });
}

// Manual add. We only write to storage here — MV3 forbids
// browser.permissions.request outside a user-gesture action context, so the
// actual host permission is requested on first visit via ensureAllowed().
function wireAddSite() {
  const input = $<HTMLInputElement>("new-site");
  const btn = $("add-site");
  async function add() {
    const v = input.value.trim();
    if (!v) return;
    if (!/^https?:\/\/[^/]+\//.test(v) && !/^https?:\/\/[^/]+$/.test(v)) {
      flashToast("格式应为 https://域名/*");
      return;
    }
    // Normalize to an origin glob: https://host/*
    let glob;
    try {
      const u = new URL(v);
      glob = `${u.protocol}//${u.host}/*`;
    } catch (_) {
      flashToast("URL 解析失败");
      return;
    }
    const resp = await send({ type: "add_allow", glob });
    if (resp?.ok) {
      input.value = "";
      await refreshAllowlist();
      flashToast("已添加");
    } else {
      flashToast((resp?.error as string) || "添加失败");
    }
  }
  btn.onclick = add;
  input.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key === "Enter") void add();
  });
}

// ---- render: enrollment (ADR-0021 pairing ceremony) -------------------------

// Shape of the background's getEnrollmentStatus() reply.
interface EnrollmentStatusView {
  required: boolean;
  platformSupported: boolean;
  state: "unpaired" | "pending" | "pinned" | "compromised";
  blocked: boolean;
  fingerprint?: string;
  pinnedAt?: number;
  lastVerifiedAt?: number;
  compromisedReason?: string;
  lastError?: string;
  paused?: boolean;
}

async function refreshEnrollment() {
  const st = (await send({ type: "get_enrollment" })) as EnrollmentStatusView | undefined;
  const panel = $("enroll-panel");
  if (!st) {
    panel.innerHTML = `<div class="enroll-err">无法获取配对状态(后台未响应)。</div>`;
    return;
  }
  // The compromised state must render (with its revoke control) even where
  // pairing is unavailable: the gate blocks on it regardless of platform, so
  // the N/A panel would falsely claim the bridge is unaffected.
  if (!st.platformSupported && st.state !== "compromised") {
    panel.innerHTML =
      `<div class="enroll-state">此平台没有 Secure Enclave,配对不可用(仅 macOS 支持)。</div>` +
      `<div class="enroll-meta">这不会阻断桥接:桥接以基础认证运行` +
      `(Linux:UDS + peer-UID + HMAC + 二进制签名校验;Windows:仅 HMAC)。` +
      `注意,「主机二进制被同用户进程替换」这一残余风险在此平台无法由配对覆盖,详见威胁模型。</div>`;
    return;
  }
  const parts: string[] = [];
  const btns: { id: string; label: string; cls: string; msg: string; confirm?: string }[] = [];

  if (st.state === "pinned") {
    parts.push(`<div class="enroll-state ok">已配对,公钥已固定。</div>`);
    parts.push(`<div class="fp">${escapeHtml(st.fingerprint || "")}</div>`);
    const meta: string[] = [];
    if (st.pinnedAt) meta.push(`固定于 ${new Date(st.pinnedAt).toLocaleString()}`);
    meta.push(
      st.lastVerifiedAt
        ? `上次手动验证:${new Date(st.lastVerifiedAt).toLocaleString()}`
        : "尚未手动验证过",
    );
    parts.push(`<div class="enroll-meta">${escapeHtml(meta.join(" · "))}</div>`);
    btns.push({
      id: "enroll-verify",
      label: "立即验证(弹 Touch ID)",
      cls: "primary",
      msg: "enroll_verify",
    });
    btns.push({
      id: "enroll-revoke",
      label: "解除配对",
      cls: "danger",
      msg: "enroll_revoke",
      confirm: "确定解除配对?桥接会保持阻断,直到重新完成配对。",
    });
  } else if (st.state === "pending") {
    parts.push(`<div class="enroll-state bad">等待批准:对比指纹。</div>`);
    parts.push(`<div class="fp">${escapeHtml(st.fingerprint || "")}</div>`);
    parts.push(
      `<div class="enroll-meta">与终端里 <code>chromium-bridge pair</code> 打印的指纹逐字符对比;` +
        `任何差异都说明回应挑战的不是你刚配对的那个主机。</div>`,
    );
    btns.push({
      id: "enroll-approve",
      label: "指纹一致,批准",
      cls: "primary",
      msg: "enroll_approve",
    });
    btns.push({ id: "enroll-reject", label: "指纹不符,拒绝", cls: "danger", msg: "enroll_reject" });
  } else if (st.state === "compromised") {
    parts.push(`<div class="enroll-state bad">验证失败,桥接已阻断。</div>`);
    parts.push(`<div class="enroll-err">${escapeHtml(st.compromisedReason || "")}</div>`);
    parts.push(
      `<div class="enroll-meta">回应验证的不是被固定的那把钥匙。先弄清原因(是不是自己 revoke 过、` +
        `重装过主机),再解除配对并重新运行 <code>chromium-bridge pair</code>。</div>`,
    );
    btns.push({
      id: "enroll-revoke",
      label: "解除配对(之后可重新配对)",
      cls: "danger",
      msg: "enroll_revoke",
      confirm: "解除配对会清除当前固定的公钥与失败记录。确定?",
    });
  } else {
    // unpaired
    const blockedNote = st.required
      ? "桥接请求当前被拒绝,直到完成配对。"
      : "「要求主机配对」当前关闭,桥接未做主机验证。";
    parts.push(`<div class="enroll-state ${st.required ? "bad" : ""}">未配对。</div>`);
    parts.push(`<div class="enroll-meta">${escapeHtml(blockedNote)}</div>`);
    btns.push({
      id: "enroll-pair",
      label: "开始配对(弹 Touch ID)",
      cls: "primary",
      msg: "enroll_pair",
    });
  }

  if (st.lastError) {
    parts.push(`<div class="enroll-err">${escapeHtml(st.lastError)}</div>`);
  }
  parts.push(
    `<div class="enroll-actions">` +
      btns
        .map(
          (b) =>
            `<button class="${escapeAttr(b.cls)}" id="${escapeAttr(b.id)}">${escapeHtml(b.label)}</button>`,
        )
        .join("") +
      `</div>`,
  );
  panel.innerHTML = parts.join("");

  for (const b of btns) {
    $(b.id).onclick = async () => {
      if (b.confirm && !window.confirm(b.confirm)) return;
      const resp = await send({ type: b.msg });
      if (resp && resp.ok === false && resp.error) {
        flashToast(String(resp.error));
      }
      // Proof/error frames arrive asynchronously; the 2s poll below picks up
      // the state they produce.
      await refreshEnrollment();
    };
  }
}

// ---- helpers --------------------------------------------------------------

async function send(msg: object): Promise<Record<string, unknown> | undefined> {
  try {
    return (await browser.runtime.sendMessage(msg)) as Record<string, unknown> | undefined;
  } catch {
    return undefined; // background unreachable; callers render the empty state
  }
}

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
function escapeHtml(s: string) {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}
function escapeAttr(s: string) {
  return escapeHtml(s);
}

// ---- init -----------------------------------------------------------------

void (async function init() {
  const s = await loadSettings();

  // Boolean toggles. The protections (safe on / warned off) show danger styling
  // while UNCHECKED via their `<key>-warn` element; benign toggles like
  // groupTabs simply have no `-warn` element, so no styling fires.
  for (const key of [
    "requireEnrollment",
    "pageEvalEnabled",
    "evalMask",
    "confirmHighRiskClick",
    "confirmPageEval",
    "confirmTabClose",
    "warnPreciseSnapshot",
    "groupTabs",
  ] as (keyof Settings)[]) {
    const input = $<HTMLInputElement>(key);
    input.checked = s[key] !== false;
    const warn = $(`${key}-warn`);
    if (warn) warn.style.display = input.checked ? "none" : "block";
    const card = $(`card-${key}`);
    if (card && warn) card.classList.toggle("danger", !input.checked);
    renderBool(key);
  }

  // cdpMode is the inverse: DANGEROUS when ON (persistent debugger attach, CSP
  // bypassed), so its warning/danger styling shows while CHECKED. Default off.
  {
    const input = $<HTMLInputElement>("cdpMode");
    const warn = $("cdpMode-warn");
    const card = $("card-cdpMode");
    const sync = (on: boolean) => {
      if (warn) warn.style.display = on ? "block" : "none";
      if (card) card.classList.toggle("danger", on);
    };
    input.checked = s.cdpMode === true;
    sync(input.checked);
    input.addEventListener("change", (e: Event) => {
      const on = (e.target as HTMLInputElement).checked;
      sync(on);
      void saveSetting("cdpMode", on);
    });
  }

  // fileUploadEnabled and handleDialogEnabled follow the same "dangerous when
  // ON" shape as cdpMode: both gate a tool that is OFF by default (local-file
  // egress / un-confirmable blocked dialog), so their warning shows while
  // CHECKED. Default off.
  for (const key of ["fileUploadEnabled", "handleDialogEnabled"] as (keyof Settings)[]) {
    const input = $<HTMLInputElement>(key);
    const warn = $(`${key}-warn`);
    const card = $(`card-${key}`);
    const sync = (on: boolean) => {
      if (warn) warn.style.display = on ? "block" : "none";
      if (card) card.classList.toggle("danger", on);
    };
    input.checked = s[key] === true;
    sync(input.checked);
    input.addEventListener("change", (e: Event) => {
      const on = (e.target as HTMLInputElement).checked;
      sync(on);
      void saveSetting(key, on);
    });
  }

  // "Allow all sites" toggle — special wiring (permission request on enable).
  // Derive the initial checkbox state from BOTH the stored setting and whether
  // the <all_urls> permission is actually held, so they can't drift apart.
  {
    const held = await browser.permissions.contains({ origins: ["<all_urls>"] });
    const effective = s.allowAllSites === true && held;
    const input = $<HTMLInputElement>("allowAllSites");
    input.checked = effective;
    // Persist the effective value in case they had drifted.
    if (effective !== (s.allowAllSites === true)) {
      await browser.storage.local.set({ allowAllSites: effective });
    }
    const warn = $("allowAllSites-warn");
    if (warn) warn.style.display = effective ? "block" : "none";
    const card = $("card-allowAllSites");
    if (card) card.classList.toggle("danger", effective);
    wireAllowAllSites();
  }

  // Number fields.
  for (const key of [
    "confirmGraceMs",
    "clickToastTimeoutMs",
    "evalToastTimeoutMs",
    "hostReverifyMs",
  ] as (keyof Settings)[]) {
    const input = $<HTMLInputElement>(key);
    input.value = String(s[key]);
    renderNumber(key);
  }

  // Tools grid.
  renderToolsGrid(s.disabledTools);

  // Allowlist.
  await refreshAllowlist();
  wireAddSite();

  // Enrollment panel. Proof/error frames land in the background asynchronously
  // (a Touch ID prompt can take a while), so poll while the page is open.
  await refreshEnrollment();
  setInterval(refreshEnrollment, 2000);
})();
