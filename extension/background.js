// background.js — MV3 Service Worker.
//
// Responsibilities:
//   - Maintain a native-messaging Port to the browser-bridge host.
//   - Reconnect automatically (MV3 SWs are killed ~every 5 min, and the host
//     process is killed by Chrome whenever the Port closes — we must
//     re-establish both on startup and after any disconnect).
//   - Dispatch inbound BridgeReq messages to the right tab's content script,
//     and route the content script's response back through the Port.
//   - Enforce the domain allowlist: an op targeting a non-allowlisted origin
//     is rejected with a clear error, and the popup is asked to prompt the
//     user.
//
// State kept in chrome.storage.local (survives SW restarts):
//   - allowlist: string[] of origin globs like "https://example.com/*"

const NATIVE_HOST = "com.zcode.browser_bridge";

// ---- native port lifecycle ------------------------------------------------

let port = null;       // current chrome.runtime.Port to the native host
let portOk = false;    // did the most recent connect succeed?
let reconnectTimer = null;

function connectNative() {
  // Tear down any previous handle first.
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST);
    portOk = true;
    console.log("[bb] native host connected");
    port.onMessage.addListener(onNativeMessage);
    port.onDisconnect.addListener(onNativeDisconnect);
  } catch (e) {
    portOk = false;
    console.error("[bb] connectNative threw", e);
    scheduleReconnect();
  }
}

function onNativeDisconnect(p) {
  portOk = false;
  port = null;
  const err = chrome.runtime.lastError;
  console.warn("[bb] native host disconnected:", err?.message || "unknown");
  // Chrome kills the host process when the Port drops. Reconnect so a fresh
  // host is spawned — but back off to avoid a tight loop if the host is
  // genuinely unavailable (e.g. install not finished).
  scheduleReconnect();
}

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectNative();
  }, 2000);
}

// ---- inbound requests from the host (→ forwarded to content scripts) -----

function onNativeMessage(msg) {
  // Each message is a BridgeReq: { id, op, tabId?, args }.
  if (!msg || typeof msg.id === "undefined" || !msg.op) {
    console.warn("[bb] malformed BridgeReq", msg);
    return;
  }
  dispatch(msg).then(
    (data) => sendResponse(msg.id, true, data),
    (err) => sendResponse(msg.id, false, undefined, String(err?.message || err || "error"))
  );
}

function sendResponse(id, ok, data, error) {
  if (!port) return; // host gone; nothing to do
  try {
    port.postMessage({ id, ok, data, error: ok ? undefined : error });
  } catch (e) {
    // Port likely closed; the disconnect handler will reconnect.
    console.warn("[bb] postMessage failed", e);
  }
}

// ---- dispatch: route an op to the tab that should act ---------------------

async function dispatch(req) {
  const { op, args } = req;

  // Tab-level ops handled directly here (no content script needed).
  switch (op) {
    case "tab_list":
      return await tabList();
    case "tab_focus":
      return await tabFocus(args.tabId);
    case "tab_open":
      return await tabOpen(args.url);
    case "tab_close":
      return await tabClose(args.tabId);
  }

  // Page-level ops need a content script in the target tab.
  const tab = await resolveTargetTab(req.tabId);
  await ensureAllowed(tab.url);
  await injectIfNeeded(tab.id);
  // content.js listens for these and replies.
  const resp = await chrome.tabs.sendMessage(tab.id, { op, args, tabId: tab.id });
  if (resp && resp.__error) throw new Error(resp.__error);
  return resp;
}

// ---- tab-level operations -------------------------------------------------

async function tabList() {
  const tabs = await chrome.tabs.query({});
  return tabs.map((t) => ({
    id: t.id,
    title: t.title,
    url: t.url,
    active: t.active,
    windowId: t.windowId,
  }));
}

async function tabFocus(tabId) {
  const t = await chrome.tabs.update(tabId, { active: true });
  await chrome.windows.update(t.windowId, { focused: true });
  return { focused: tabId };
}

async function tabOpen(url) {
  await ensureAllowed(url);
  const t = await chrome.tabs.create({ url });
  return { opened: t.id, url };
}

async function tabClose(tabId) {
  await chrome.tabs.remove(tabId);
  return { closed: tabId };
}

// ---- target tab resolution ------------------------------------------------

async function resolveTargetTab(maybeTabId) {
  if (maybeTabId) {
    return await chrome.tabs.get(maybeTabId);
  }
  const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!active) throw new Error("no active tab");
  return active;
}

async function injectIfNeeded(tabId) {
  // The content script is declared in the manifest and auto-injected on page
  // load, but for tabs that were open before install, or for
  // restricted pages, it may be missing. Ping; if no response, inject.
  try {
    await chrome.tabs.sendMessage(tabId, { op: "ping" });
  } catch (e) {
    // Not injected yet — inject now (requires scripting permission + host).
    const tab = await chrome.tabs.get(tabId);
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content.js"],
    });
    try {
      await chrome.scripting.insertCSS({
        target: { tabId },
        files: ["toast.css"],
      });
    } catch (_) {
      // CSS injection can fail on some pages; not fatal.
    }
  }
}

// ---- allowlist enforcement ------------------------------------------------

const STORAGE_KEY = "allowlist";
const SENSITIVE_HOSTS = [
  // High-risk domains where we always require confirmation, never auto-allow.
  // Kept minimal for v0.1; extend as needed.
];

async function getAllowlist() {
  const { [STORAGE_KEY]: list } = await chrome.storage.local.get(STORAGE_KEY);
  return Array.isArray(list) ? list : [];
}

async function setAllowlist(list) {
  await chrome.storage.local.set({ [STORAGE_KEY]: list });
}

function originGlobOf(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/*`;
  } catch (_) {
    return null;
  }
}

function matchesAny(glob, list) {
  return list.some((pattern) => simpleMatch(pattern, glob));
}

// Minimal glob match: supports trailing * only. Good enough for "host/*".
function simpleMatch(pattern, target) {
  if (pattern === target) return true;
  if (pattern.endsWith("/*")) {
    const base = pattern.slice(0, -2); // drop "/*"
    return target === base || target.startsWith(base + "/");
  }
  if (pattern.endsWith("*")) {
    return target.startsWith(pattern.slice(0, -1));
  }
  return false;
}

async function ensureAllowed(url) {
  const glob = originGlobOf(url);
  if (!glob) throw new Error(`cannot parse url: ${url}`);
  const list = await getAllowlist();
  if (matchesAny(glob, list)) return;
  // Not allowlisted → ask the user via the popup. We open the popup by
  // setting a badge and storing a pending request; the popup, when opened,
  // reads it. If the popup isn't opened within the timeout, we reject.
  const allowed = await promptUserForAllow(glob);
  if (!allowed) {
    throw new Error(`origin not allowed by user: ${glob}`);
  }
}

// Ask the user to approve a new origin. We surface a notification badge; the
// popup handles the actual yes/no. Resolves true/false.
function promptUserForAllow(glob) {
  return new Promise((resolve) => {
    const reqId = `allow_${Date.now()}`;
    pendingAllowRequests.set(reqId, { glob, resolve });
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#d9534f" });
    chrome.storage.local.set({ pendingAllow: { id: reqId, glob } });
    // Auto-reject after 60s.
    setTimeout(() => {
      if (pendingAllowRequests.has(reqId)) {
        pendingAllowRequests.delete(reqId);
        chrome.storage.local.remove("pendingAllow");
        maybeClearBadge();
        resolve(false);
      }
    }, 60000);
  });
}

const pendingAllowRequests = new Map();

function maybeClearBadge() {
  if (pendingAllowRequests.size === 0) {
    chrome.action.setBadgeText({ text: "" });
  }
}

// The popup calls this (via runtime message) to resolve a pending allow.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === "resolve_allow") {
    const { id, allow } = msg;
    const pending = pendingAllowRequests.get(id);
    if (pending) {
      pendingAllowRequests.delete(id);
      maybeClearBadge();
      if (allow) {
        getAllowlist().then((list) => {
          if (!list.includes(pending.glob)) list.push(pending.glob);
          setAllowlist(list).then(() => {
            pending.resolve(true);
            sendResponse({ ok: true });
          });
        });
        return true; // async
      } else {
        pending.resolve(false);
        sendResponse({ ok: true });
        return false;
      }
    }
    sendResponse({ ok: false, error: "no such pending request" });
    return false;
  }
  if (msg?.type === "get_allowlist") {
    getAllowlist().then((list) => sendResponse({ list }));
    return true;
  }
  if (msg?.type === "remove_allow") {
    getAllowlist().then((list) => {
      const next = list.filter((g) => g !== msg.glob);
      setAllowlist(next).then(() => sendResponse({ ok: true, list: next }));
    });
    return true;
  }
  if (msg?.type === "get_status") {
    sendResponse({ nativeConnected: portOk });
    return false;
  }
  if (msg?.type === "capture_visible_tab") {
    // Content scripts can't call chrome.tabs.captureVisibleTab; proxy here.
    chrome.tabs.captureVisibleTab(undefined, { format: "png" }, (dataUrl) => {
      if (chrome.runtime.lastError) {
        sendResponse({ error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ dataUrl });
      }
    });
    return true; // async
  }
});

// ---- startup ---------------------------------------------------------------

chrome.runtime.onStartup.addListener(connectNative);
chrome.runtime.onInstalled.addListener(connectNative);
// Also connect eagerly when the SW wakes for any reason. connectNative is
// idempotent-ish: if a port already exists it creates a new one and the old
// is replaced.
connectNative();
