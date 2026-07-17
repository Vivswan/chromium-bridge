// popup.ts — runs when the user clicks the extension icon. Handles two jobs:
//   1. Show connection status + current allowlist (with revoke).
//   2. If background asked the user to approve a new origin (badge "!" + a
//      `pendingAllow` entry in storage), show the approve/deny UI. Approving
//      ALSO requests the host permission via chrome.permissions.request —
//      this must happen in the popup (a user-gesture context), since service
//      workers cannot request permissions.

import { PendingAllowSchema } from "@chromium-bridge/shared";

function $<T extends HTMLElement = HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

async function refreshStatus() {
  const status = await send({ type: "get_status" });
  const enroll = (await send({ type: "get_enrollment" })) as
    | { state?: string; blocked?: boolean }
    | undefined;
  const dot = $("dot");
  const connected = Boolean(status?.nativeConnected);
  let text: string;
  if (enroll?.blocked) {
    // Enrollment gate is closed: connected or not, no bridge op will run.
    text =
      enroll.state === "pending"
        ? "Blocked: approve the host fingerprint in Settings"
        : enroll.state === "compromised"
          ? "Blocked: host key verification failed (see Settings)"
          : "Blocked: host pairing required (see Settings)";
    dot.className = "dot bad";
  } else {
    text = connected ? "Connected to bridge" : "Not connected (is your MCP client running?)";
    dot.className = `dot ${connected ? "ok" : "bad"}`;
  }
  $("status-text").textContent = text;
}

async function refreshList() {
  const resp = await send({ type: "get_allowlist" });
  const list = (resp?.list as string[]) || [];
  $("empty").style.display = list.length ? "none" : "block";
  $("list").innerHTML = list
    .map(
      (g) =>
        `<div class="item"><code>${escapeHtml(g)}</code>` +
        `<button class="danger" data-glob="${escapeAttr(g)}">Revoke</button></div>`,
    )
    .join("");
  // Wire revoke buttons.
  document.querySelectorAll<HTMLButtonElement>(".item button").forEach((b) => {
    b.onclick = async () => {
      const glob = b.getAttribute("data-glob")!;
      await send({ type: "remove_allow", glob });
      await refreshList();
    };
  });
}

async function refreshPending() {
  const { pendingAllow } = await chrome.storage.local.get("pendingAllow");
  const parsed = PendingAllowSchema.safeParse(pendingAllow);
  if (parsed.success) {
    const { id, glob } = parsed.data;
    $("pending").style.display = "block";
    $("pending-glob").textContent = glob;
    $("allow").onclick = () => resolvePending(id, glob, true);
    $("deny").onclick = () => resolvePending(id, glob, false);
  } else {
    $("pending").style.display = "none";
  }
}

async function resolvePending(id: string, glob: string, allow: boolean) {
  if (allow) {
    // Request host permission at the same time as recording the allow. The
    // origin glob looks like "https://example.com/*"; convert to a match
    // pattern for permissions.request.
    const pattern = globToPattern(glob);
    try {
      const granted = await chrome.permissions.request({ origins: [pattern] });
      if (!granted) {
        // User declined the OS prompt → treat as deny.
        await send({ type: "resolve_allow", id, allow: false });
        $("pending").style.display = "none";
        return;
      }
    } catch (e) {
      console.warn("[bb] permissions.request failed", e);
    }
  }
  await send({ type: "resolve_allow", id, allow });
  $("pending").style.display = "none";
  await refreshList();
}

function globToPattern(glob: string) {
  // "https://example.com/*" is already a valid match pattern; pass through.
  // If it somehow lacks the trailing *, add it.
  return glob.endsWith("/*") ? glob : `${glob}*`;
}

function send(msg: object): Promise<Record<string, unknown> | undefined> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => resolve(resp));
  });
}

const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};
function escapeHtml(s: string) {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}
function escapeAttr(s: string) {
  return escapeHtml(s);
}

// Open the full settings page (options_ui). The evalMask toggle and all other
// security/tool/timeout settings now live there.
$("open-settings").addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

void refreshStatus();
void refreshList();
void refreshPending();
