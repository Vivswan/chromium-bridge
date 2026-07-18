/**
 * DOM-layer tests for src/apps/extension/content.js - runs the REAL content.js source
 * against a real headless Chrome page via the DevTools Protocol.
 *
 * What this validates (that tests/protocol/e2e.py cannot): the actual DOM logic -
 * TreeWalker snapshot, accessible-name computation, native-setter fill,
 * Function-constructor eval, localStorage reads, Toast injection - against
 * real browser DOM, not mocks.
 *
 * What this does NOT cover (lives in background.js, not content.js):
 * page_snapshot_precise (chrome.debugger), cookie_get (chrome.cookies).
 *
 * Run:  bun tests/browser/dom_test.ts
 * Requires: Chrome (uses the system Chrome in headless mode), bun.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type Subprocess, spawn } from "bun";
import { assertIsolatedBrowserOrSkip } from "./browser-safety";

const REPO = path.resolve(import.meta.dir, "../..");
// The built bundle (esbuild strips TS types from src/content.ts). Run
// `bun run --cwd src/apps/extension build` first; `run_all.ts` / `just` do this.
const CONTENT_JS = path.join(
  REPO,
  "build",
  "extension",
  "chrome-mv3",
  "content-scripts",
  "content.js",
);
const FIXTURES_DIR = path.join(REPO, "tests", "fixtures");
// The guard (assertIsolatedBrowserOrSkip, called in main) verifies CHROME_BIN
// by --version before use; it is only ever an isolated Chrome for Testing here.
const CHROME = process.env.CHROME_BIN ?? "";

/** Resolve a fixture filename to its file:// URL. */
function fixtureUrl(name: string): string {
  return `file://${path.join(FIXTURES_DIR, name)}`;
}

// ─── assertion helpers (same style as tests/protocol/e2e.py) ────────────────────────
let Pass = 0;
let Fail = 0;
function check(cond: boolean, label: string): void {
  if (cond) {
    Pass++;
    console.log(`  PASS  ${label}`);
  } else {
    Fail++;
    console.log(`  FAIL  ${label}`);
  }
}

// ─── headless Chrome process ───────────────────────────────────────────────
class Chrome {
  proc: Subprocess;
  port: number;
  userDataDir: string;
  constructor(port = 9444) {
    this.port = port;
    // Throwaway profile: never touch a real browser profile.
    this.userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bb-dom-"));
    this.proc = spawn({
      cmd: [
        CHROME,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        "--no-first-run",
        "--no-default-browser-check",
        `--user-data-dir=${this.userDataDir}`,
        `--remote-debugging-port=${port}`,
        "--remote-allow-origins=*",
        "about:blank",
      ],
      stdout: "ignore",
      stderr: "ignore",
    });
  }
  async waitReady(timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`http://127.0.0.1:${this.port}/json/version`);
        if (r.ok) return;
      } catch {}
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`Chrome did not become ready on port ${this.port}`);
  }
  async stop(): Promise<void> {
    try {
      this.proc.kill();
      // Await exit so Chrome has released the profile before we remove it.
      await this.proc.exited;
    } catch {}
    try {
      fs.rmSync(this.userDataDir, { recursive: true, force: true });
    } catch {}
  }
}

// ─── minimal CDP client over WebSocket ─────────────────────────────────────
class Page {
  ws: WebSocket;
  sessionId: string;
  private id = 0;
  private pending = new Map<number, (v: any) => void>();
  private constructor(ws: WebSocket, sessionId: string) {
    this.ws = ws;
    this.sessionId = sessionId;
    ws.onmessage = (e: MessageEvent) => {
      const msg = JSON.parse(e.data as string);
      if (msg.id && this.pending.has(msg.id)) {
        this.pending.get(msg.id)!(msg);
        this.pending.delete(msg.id);
      }
    };
  }
  static async connect(port: number): Promise<Page> {
    // Find the page target.
    const listRes = await fetch(`http://127.0.0.1:${port}/json/list`);
    const targets = (await listRes.json()) as any[];
    const page = targets.find((t) => t.type === "page");
    if (!page) throw new Error("no page target");
    // Connect to the browser-level WS, then attach via flattened session.
    const verRes = await fetch(`http://127.0.0.1:${port}/json/version`);
    const ver = (await verRes.json()) as any;
    const wsUrl = ver.webSocketDebuggerUrl;
    const ws = new WebSocket(wsUrl);
    await new Promise<void>((r, rej) => {
      ws.onopen = () => r();
      ws.onerror = () => rej(new Error("ws open failed"));
    });
    // Attach to the page target to get a sessionId for flattened protocol.
    const attach = await Page.sendRaw(ws, "Target.attachToTarget", {
      targetId: page.id,
      flatten: true,
    });
    const sessionId = attach.result.sessionId;
    const inst = new Page(ws, sessionId);
    return inst;
  }
  private static sendRaw(ws: WebSocket, method: string, params: any): Promise<any> {
    const id = ++Page._staticId;
    return new Promise((resolve) => {
      const onMsg = (e: MessageEvent) => {
        const msg = JSON.parse(e.data as string);
        if (msg.id === id) {
          ws.removeEventListener("message", onMsg as any);
          resolve(msg);
        }
      };
      ws.addEventListener("message", onMsg as any);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }
  private static _staticId = 0;
  send(method: string, params: any = {}): Promise<any> {
    const id = ++this.id;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.ws.send(JSON.stringify({ id, method, params, sessionId: this.sessionId }));
    });
  }
  /** Evaluate an expression in the page, return the value (must be JSON via returnByValue). */
  /** Navigate the page to a URL. Enables switching fixtures per test. */
  async navigate(url: string, settleMs = 400): Promise<void> {
    await this.send("Page.enable", {});
    await this.send("Page.navigate", { url });
    // Give inline scripts time to run. CDP doesn't expose a clean "load done"
    // without listening to events; a short settle is reliable for our static
    // fixtures.
    await new Promise((r) => setTimeout(r, settleMs));
  }
  async evaluate(expr: string): Promise<any> {
    const r = await this.send("Runtime.evaluate", {
      expression: expr,
      returnByValue: true,
      awaitPromise: true,
    });
    if (r.result?.exceptionDetails) {
      throw new Error(
        "evaluate threw: " +
          JSON.stringify(
            r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text,
          ),
      );
    }
    return r.result?.result?.value;
  }
  /** Evaluate a function with arguments (safer for injecting big strings). */
  async callFunction(fnDecl: string, args: any[]): Promise<any> {
    const r = await this.send("Runtime.evaluate", {
      expression: `(${fnDecl})(${args.map((a) => JSON.stringify(a)).join(",")})`,
      returnByValue: true,
      awaitPromise: true,
    });
    if (r.result?.exceptionDetails) {
      throw new Error(
        "callFunction threw: " +
          JSON.stringify(
            r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text,
          ),
      );
    }
    return r.result?.result?.value;
  }
}

// ─── content.js injection harness ──────────────────────────────────────────

/** Inject chrome.* stubs into the page before content.js loads.
 * Captures the onMessage listener so tests can drive it. */
async function injectStub(page: Page, opts: { evalMask?: boolean } = {}): Promise<void> {
  const evalMask = opts.evalMask ?? true;
  await page.evaluate(`
    (function(){
      window.__bbListeners = [];
      window.__bbLastResp = undefined;
      window.__bbRespSeq = 0;
      globalThis.chrome = globalThis.chrome || {};
      chrome.runtime = {
        onMessage: { addListener: function(fn){ window.__bbListeners.push(fn); } },
        sendMessage: function(msg, cb){
          // screenshot capture stub: respond with empty (tests don't check pixels)
          if (cb) cb({ dataUrl: "" });
        },
        lastError: undefined,
      };
      chrome.storage = {
        local: {
          get: function(key, cb){
            if (cb) cb({ evalMask: ${JSON.stringify(evalMask)} });
          },
        },
      };
    })();
  `);
}

/** Read and inject the real content.js source. Returns the number of
 * registered listeners (should be 1). Clears the load guard first so the
 * IIFE re-runs (enables per-test re-injection). */
async function loadContentJs(page: Page): Promise<void> {
  const src = fs.readFileSync(CONTENT_JS, "utf8");
  // Clear the load guard so the IIFE's `if (window.__chromiumBridgeLoaded) return`
  // doesn't short-circuit on re-injection between tests.
  await page.evaluate("delete window.__chromiumBridgeLoaded;");
  // Wrap in an IIFE-protecting eval so top-level `return` inside content.js's
  // own IIFE works. content.js is already an IIFE, so direct eval is fine.
  await page.evaluate(src);
}

/** Invoke a content.js op via the captured onMessage listener. Returns the
 * sendResponse payload (the op's result object). */
async function invoke(page: Page, op: string, args: any = {}, timeoutMs = 8000): Promise<any> {
  // Reset the response slot, then call the listener. The listener returns true
  // (async) and eventually calls sendResponse with the result.
  await page.evaluate(`
    (function(){
      window.__bbLastResp = undefined;
      window.__bbRespSeq++;
      var seq = window.__bbRespSeq;
      window.__bbWaitSeq = seq;
      var sendResponse = function(r){
        if (window.__bbWaitSeq === seq) window.__bbLastResp = r;
      };
      var listener = window.__bbListeners[0];
      if (!listener) throw new Error("no content.js listener registered");
      listener({ op: ${JSON.stringify(op)}, args: ${JSON.stringify(args)} }, {}, sendResponse);
    })();
  `);
  // Poll for the response (handler is async).
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const resp = await page.evaluate("window.__bbLastResp");
    if (resp !== undefined && resp !== null) return resp;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`invoke('${op}') timed out after ${timeoutMs}ms`);
}

/** Click a Toast button (Allow/Deny/Cancel) in the page - for testing the
 * high-risk confirmation flow. */

// ─── tests ─────────────────────────────────────────────────────────────────
// (added in the next step)

async function main() {
  // SAFETY: refuse anything that is not an isolated Chrome for Testing.
  assertIsolatedBrowserOrSkip();
  // Sanity: content.js source must exist.
  if (!fs.existsSync(CONTENT_JS)) {
    console.error(`content.js not found at ${CONTENT_JS}`);
    process.exit(2);
  }

  console.log("starting headless Chrome...");
  const chrome = new Chrome(9444);
  try {
    await chrome.waitReady();
    const page = await Page.connect(9444);
    // Give the page's inline <script> (localStorage setup) time to run.
    await new Promise((r) => setTimeout(r, 300));

    await runAllTests(page);
  } finally {
    await chrome.stop();
  }
  console.log(`\n${"=".repeat(40)}\n${Pass} passed, ${Fail} failed`);
  process.exit(Fail > 0 ? 1 : 0);
}

async function runAllTests(page: Page): Promise<void> {
  await testSnapshot(page);
  await testClick(page);
  await testFill(page);
  await testText(page);
  await testEvalRaw(page);
  await testEvalUnmasked(page);
  await testEvalErrorAndSerialize(page);
  await testStorageGet(page);
  await testWaitForNav(page);
  await testNoInPageToast(page);
  await testPing(page);
  await testShadowDom(page);
  await testIframe(page);
  await testDynamicReloadSnapshot(page);
}

/** Re-inject content.js fresh for each test so refCounter / refMap reset.
 * `fixture` selects which HTML file to load (default page.html). */
async function freshLoad(
  page: Page,
  opts: { evalMask?: boolean; fixture?: string } = {},
): Promise<void> {
  const name = opts.fixture || "page.html";
  const url = fixtureUrl(name);
  // Navigate (or reload) to wipe all DOM mutations (toasts, data-zcb-ref
  // attrs, onclick counts). Navigate works for about:blank→fixture and
  // also reloads if already on the same URL.
  await page.navigate(url);
  await injectStub(page, opts);
  await loadContentJs(page);
}

// ── test: page_snapshot ────────────────────────────────────────────────────
async function testSnapshot(page: Page): Promise<void> {
  console.log("\n[test] page_snapshot - refs, roles, names, visibility filter");
  await freshLoad(page);
  const resp = await invoke(page, "page_snapshot", {});
  check(!resp.__error, `snapshot returns without error: ${resp.__error || "ok"}`);
  if (resp.__error) return;
  const nodes = resp.nodes || [];
  check(resp.refCount === nodes.length, "refCount matches nodes length");
  check(nodes.length > 0, "snapshot found interactive elements");

  const byId: Record<string, any> = {};
  for (const n of nodes) byId[n.ref] = n;

  // Role checks: input:text → textbox, button → button, link → link, checkbox, radio.
  const search = nodes.find((n: any) => n.selector?.includes("#search"));
  check(!!search, "snapshot includes #search input");
  check(search?.role === "textbox", `#search role is textbox (got ${search?.role})`);
  check(search?.name === "Search box", `#search name from aria-label (got ${search?.name})`);

  const go = nodes.find((n: any) => n.selector?.includes("#go"));
  check(go?.role === "button", "#go role is button");
  check(go?.name === "Search", "#go name from innerText");

  const link = nodes.find((n: any) => n.selector?.includes("#link1"));
  check(link?.role === "link", "#link1 role is link");

  const cb = nodes.find((n: any) => n.selector?.includes("#cb"));
  check(cb?.role === "checkbox", "#cb role is checkbox");

  // accessible-name via aria-labelledby.
  const email = nodes.find((n: any) => n.selector?.includes("#email"));
  check(email?.name === "Email address", `#email name via aria-labelledby (got ${email?.name})`);

  // accessible-name via wrapping <label>.
  const user = nodes.find((n: any) => n.selector?.includes("#user"));
  check(user?.name === "Username", `#user name via wrapping <label> (got ${user?.name})`);

  // Visibility filter: hidden buttons must NOT appear.
  const hiddenBtn = nodes.find((n: any) => n.selector?.includes("#hidden-btn"));
  check(!hiddenBtn, "display:none button excluded from snapshot");
  const axHiddenBtn = nodes.find((n: any) => n.selector?.includes("#ax-hidden-btn"));
  check(!axHiddenBtn, "aria-hidden subtree button excluded");

  // Refs are stable strings with the 'e' prefix.
  check(
    nodes.every((n: any) => /^e\d+$/.test(n.ref)),
    "all refs match e<number>",
  );
}

// ── test: page_click ───────────────────────────────────────────────────────
async function testClick(page: Page): Promise<void> {
  console.log("\n[test] page_click - real DOM click + ref resolution");
  await freshLoad(page);
  // First snapshot to get refs assigned.
  const snap = await invoke(page, "page_snapshot", {});
  const plainBtn = snap.nodes.find((n: any) => n.selector?.includes("#plain-btn"));
  check(!!plainBtn, `snapshot has #plain-btn ref: ${plainBtn?.ref}`);

  // Click by ref - should actually trigger the page's onclick counter.
  const before = await page.evaluate("window.__plainClicks || 0");
  const clickResp = await invoke(page, "page_click", { ref: plainBtn.ref });
  check(!clickResp.__error, `click by ref succeeds: ${clickResp.__error || "ok"}`);
  const after = await page.evaluate("window.__plainClicks || 0");
  check(after === before + 1, `click triggered real onclick (before=${before} after=${after})`);

  // Click by selector fallback (no ref).
  const before2 = await page.evaluate("window.__plainClicks || 0");
  const clickResp2 = await invoke(page, "page_click", { selector: "#plain-btn" });
  check(!clickResp2.__error, "click by selector succeeds");
  const after2 = await page.evaluate("window.__plainClicks || 0");
  check(after2 === before2 + 1, "selector click triggered onclick");

  // Non-existent ref → clear error.
  const bad = await invoke(page, "page_click", { ref: "e999" });
  check(!!bad.__error, "click on stale ref returns error");
}

// ── test: page_fill ────────────────────────────────────────────────────────
async function testFill(page: Page): Promise<void> {
  console.log("\n[test] page_fill - native setter + framework change detection");
  await freshLoad(page);
  const resp = await invoke(page, "page_fill", { selector: "#fill-target", value: "hello" });
  check(!resp.__error, `fill succeeds: ${resp.__error || "ok"}`);

  // Value actually set on the DOM input.
  const val = await page.evaluate(`document.getElementById("fill-target").value`);
  check(val === "hello", `fill set input.value to 'hello' (got ${val})`);

  // Framework change detection: input + change events fired (recorded in event-log).
  const inputCount = await page.evaluate(
    `document.getElementById("event-log").dataset.input || "0"`,
  );
  const changeCount = await page.evaluate(
    `document.getElementById("event-log").dataset.change || "0"`,
  );
  check(parseInt(inputCount, 10) >= 1, `fill dispatched input event (${inputCount})`);
  check(parseInt(changeCount, 10) >= 1, `fill dispatched change event (${changeCount})`);
}

// ── test: page_text ────────────────────────────────────────────────────────
async function testText(page: Page): Promise<void> {
  console.log("\n[test] page_text - password masking");
  await freshLoad(page);
  const resp = await invoke(page, "page_text", {});
  check(!resp.__error, "text returns without error");
  // The password field's real value "supersecret" must NOT appear.
  check(!resp.text.includes("supersecret"), "page_text masks password value");
  check(resp.text.includes("Test Fixture"), "page_text includes page heading");
}

/** Run a page_eval op. Since ADR-0027 the content leg no longer confirms (the
 * SW gate does, off-DOM), so there is no in-page toast to approve - the eval
 * runs and returns directly. Kept as a named helper so the eval tests read
 * clearly. */
function invokeWithEvalApproval(page: Page, op: string, args: any, timeoutMs = 8000): Promise<any> {
  return invoke(page, op, args, timeoutMs);
}

// ── test: page_eval (content leg returns RAW) ──────────────────────────────
// Since ADR-0027 masking moved to the service worker's egress (egress.ts); the
// content leg executes and serializes ONLY. So the content result is the RAW
// value here; the mask is applied in the SW before it leaves the extension
// (covered by src/apps/extension/tests/background/egress.test.ts and the real-browser
// security proof). This test pins that the content leg returns the raw value.
async function testEvalRaw(page: Page): Promise<void> {
  console.log("\n[test] page_eval - content leg returns RAW (SW masks on egress)");
  await freshLoad(page, { evalMask: true });
  const resp = await invokeWithEvalApproval(page, "page_eval", {
    code: 'return localStorage.getItem("token");',
  });
  check(!resp.__evalError, "eval runs without JS error");
  check(typeof resp === "string", "eval returned a string");
  // The content leg does NOT mask; the raw JWT comes back and is masked SW-side.
  check(resp.includes("eyJhbGciOiJI"), "content leg returns the raw value (masking is SW-side)");
}

// ── test: page_eval (unmasked) ─────────────────────────────────────────────
async function testEvalUnmasked(page: Page): Promise<void> {
  console.log("\n[test] page_eval - unmasked return (evalMask: false)");
  await freshLoad(page, { evalMask: false });
  const resp = await invokeWithEvalApproval(page, "page_eval", {
    code: "return 6 * 7;",
  });
  check(!resp.__evalError, "eval runs without JS error");
  check(resp === 42, `unmasked eval returns computed value 42 (got ${resp})`);
}

// ── test: page_eval error + serialization ──────────────────────────────────
async function testEvalErrorAndSerialize(page: Page): Promise<void> {
  console.log("\n[test] page_eval - error handling + serialization");
  await freshLoad(page, { evalMask: false });

  // Thrown error → structured __evalError, not a throw.
  const errResp = await invokeWithEvalApproval(page, "page_eval", {
    code: "throw new Error('boom');",
  });
  check(errResp.__evalError === true, "thrown error surfaces as __evalError");
  check(errResp.message === "boom", "error message preserved");

  // Circular reference → serialized as [Circular].
  const circResp = await invokeWithEvalApproval(page, "page_eval", {
    code: "var a = {x:1}; a.self = a; return a;",
  });
  check(circResp.self === "[Circular]", "circular ref serialized as [Circular]");

  // DOM element → short tag descriptor.
  const elResp = await invokeWithEvalApproval(page, "page_eval", {
    code: 'return document.getElementById("search");',
  });
  check(
    typeof elResp === "string" && elResp.includes("input"),
    "DOM element serialized as <input...> tag",
  );
}

// ── test: storage_get (content leg returns RAW) ────────────────────────────
// Like page_eval, storage_get masking moved to the SW egress (ADR-0027,
// always-on per ADR-0010). The content leg returns RAW values; the SW masks
// them before they leave (covered by egress.test.ts). This test pins the raw
// read + the DOM-side shape (found/missing, session vs local).
async function testStorageGet(page: Page): Promise<void> {
  console.log("\n[test] storage_get - content leg returns RAW (SW masks on egress)");
  await freshLoad(page);

  // Single key with JWT - RAW here (masked SW-side).
  const tokenResp = await invoke(page, "storage_get", { type: "local", key: "token" });
  check(tokenResp.found === true, "storage_get found token key");
  check(tokenResp.value.includes("eyJhbGciOiJI"), "content leg returns the raw value");

  // Plain value passes through.
  const plainResp = await invoke(page, "storage_get", { type: "local", key: "plain" });
  check(plainResp.value === "hello world", "plain value returned as-is");

  // Hex id - returned raw (the exact seeded value), not masked here.
  const hexResp = await invoke(page, "storage_get", { type: "local", key: "hexid" });
  check(
    hexResp.value === "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
    "hex id returned raw (exact seeded value, unmasked)",
  );

  // Missing key.
  const missingResp = await invoke(page, "storage_get", { key: "nonexistent" });
  check(missingResp.found === false, "missing key → found:false");

  // sessionStorage.
  const sessResp = await invoke(page, "storage_get", { type: "session", key: "stoken" });
  check(sessResp.found === true, "sessionStorage accessible");
}

// ── test: page_wait_for(nav) ───────────────────────────────────────────────
async function testWaitForNav(page: Page): Promise<void> {
  console.log("\n[test] page_wait_for - nav/load condition");
  await freshLoad(page);
  const resp = await invoke(page, "page_wait_for", { nav: true, timeoutMs: 1000 });
  check(!resp.__error, "nav wait returns without timeout");
  check(resp.nav === true, "nav wait result marks nav:true");
  check(resp.readyState === "complete", "nav wait sees complete readyState");
}

// ── test: high-risk click injects NO in-page toast (ADR-0027) ──────────────
// The high-risk confirmation moved OFF the page-reachable DOM to an
// extension-owned window; the risk decision + confirmation run in the service
// worker BEFORE the op reaches the content leg. So the content leg receives a
// plain page_click and just performs it - it must NOT inject any toast into
// the page. (The off-DOM confirmation + the click's approved-target binding
// are proven by tests/browser/security_browser_test.ts and the SW-side gate.test.ts.)
async function testNoInPageToast(page: Page): Promise<void> {
  console.log("\n[test] high-risk click injects NO in-page toast (off-DOM, ADR-0027)");
  await freshLoad(page);
  const snap = await invoke(page, "page_snapshot", {});
  const go = snap.nodes.find((n: any) => n.selector?.includes("#go"));
  check(go?.role === "button", "#go is the submit button");

  const resp = await invoke(page, "page_click", { ref: go.ref });
  check(!resp.__error, `content click proceeds: ${resp.__error || "ok"}`);
  const count = await page.evaluate("window.__clickCount || 0");
  check(count >= 1, "content click triggered onclick");
  // No confirmation UI of any kind was injected: the content leg never creates
  // the toast host element, and no danger/eval/toast card exists anywhere.
  const toastDom = await page.evaluate(`
    (function(){
      return {
        host: !!document.getElementById("__zcb_toast_host"),
        anyCard: !!document.querySelector(".zcb-eval-card, .zcb-toast-card, .zcb-danger, .zcb-toast-allow"),
      };
    })();
  `);
  check(!toastDom.host && !toastDom.anyCard, "no in-page confirmation UI was injected");
}

// ── test: ping ─────────────────────────────────────────────────────────────
async function testPing(page: Page): Promise<void> {
  console.log("\n[test] ping op");
  await freshLoad(page);
  const resp = await invoke(page, "ping", {});
  check(resp.pong === true, "ping returns {pong:true}");
}

// ── test: shadow DOM (content-script limitation) ──────────────────────────
async function testShadowDom(page: Page): Promise<void> {
  console.log("\n[test] shadow DOM - snapshot does not cross shadow boundary");
  await freshLoad(page, { fixture: "shadow.html" });

  // Sanity: the fixture set up the shadow roots as expected.
  const openHasBtn = await page.evaluate(
    `!!window.__openRoot && !!window.__openRoot.querySelector("#shadow-btn")`,
  );
  check(openHasBtn, "fixture: open shadow root has #shadow-btn");
  const closedHostShadow = await page.evaluate("window.__closedHostHasShadow");
  check(closedHostShadow === false, "fixture: closed shadow root unreachable via .shadowRoot");

  // snapshot must find the plain top-level button but NOT the shadow buttons.
  const resp = await invoke(page, "page_snapshot", {});
  check(!resp.__error, "snapshot runs without error");
  const plainFound = resp.nodes.some((n: any) => n.selector?.includes("#plain"));
  check(plainFound, "snapshot finds the plain (non-shadow) button");
  const shadowBtnFound = resp.nodes.some((n: any) => n.name === "In Open Shadow");
  check(!shadowBtnFound, "open shadow button NOT in snapshot (TreeWalker boundary)");
  const closedShadowBtnFound = resp.nodes.some((n: any) => n.name === "In Closed Shadow");
  check(!closedShadowBtnFound, "closed shadow button NOT in snapshot");

  // Clicking the plain button via its ref still works (content.js otherwise
  // functional on the top frame).
  const plainNode = resp.nodes.find((n: any) => n.selector?.includes("#plain"));
  const clickResp = await invoke(page, "page_click", { ref: plainNode.ref });
  check(!clickResp.__error, "click plain button via ref works");
}

// ── test: iframe (content-script top-frame-only limitation) ────────────────
async function testIframe(page: Page): Promise<void> {
  console.log("\n[test] iframe - top-frame snapshot excludes iframe content");
  await freshLoad(page, { fixture: "iframe.html" });

  // Wait for the iframe to actually load.
  for (let i = 0; i < 20; i++) {
    const ready = await page.evaluate("window.__iframeReady === true");
    if (ready) break;
    await new Promise((r) => setTimeout(r, 100));
  }
  const iframeReady = await page.evaluate("window.__iframeReady === true");
  check(iframeReady, "iframe finished loading");

  const resp = await invoke(page, "page_snapshot", {});
  check(!resp.__error, "snapshot runs without error");

  // Top-frame button IS in snapshot.
  const topFound = resp.nodes.some((n: any) => n.selector?.includes("#top-btn"));
  check(topFound, "snapshot finds top-frame #top-btn");

  // Iframe button is NOT in snapshot (content.js not injected into iframe).
  const iframeBtnFound = resp.nodes.some((n: any) => n.name === "In iframe");
  check(!iframeBtnFound, "iframe button NOT in top-frame snapshot (no all_frames)");

  // page_click targeting the iframe button via selector must fail (it's in a
  // different document; querySelector on the top document returns null).
  const badClick = await invoke(page, "page_click", { selector: "#iframe-btn" });
  check(!!badClick.__error, "click on iframe-resident selector fails as expected");
}

// ── test: dynamic insertion + re-snapshot ref stability ────────────────────
async function testDynamicReloadSnapshot(page: Page): Promise<void> {
  console.log("\n[test] dynamic insertion - re-snapshot + ref stability");
  await freshLoad(page, { fixture: "dynamic.html" });

  // Snapshot #1: two interactive elements (button#btn-a + input#inp-a).
  const snap1 = await invoke(page, "page_snapshot", {});
  check(!snap1.__error, "snapshot #1 runs");
  const btnA1 = snap1.nodes.find((n: any) => n.selector?.includes("#btn-a"));
  const inpA1 = snap1.nodes.find((n: any) => n.selector?.includes("#inp-a"));
  check(!!btnA1 && !!inpA1, "snapshot #1 found #btn-a and #inp-a");
  const count1 = snap1.refCount;
  const btnARef = btnA1.ref;
  check(/^e\d+$/.test(btnARef), `snapshot #1 assigned an 'e' ref to #btn-a: ${btnARef}`);

  // Insert a new button dynamically.
  const added = await page.evaluate("window.__addButton()");
  check(added === true, "dynamic button inserted");

  // Snapshot #2: should now include the new button.
  const snap2 = await invoke(page, "page_snapshot", {});
  check(!snap2.__error, "snapshot #2 runs");
  const count2 = snap2.refCount;
  check(count2 === count1 + 1, `snapshot #2 refCount grew by 1 (${count1}→${count2})`);

  // CRITICAL: #btn-a's ref must be STABLE across snapshots (assignRef reuses
  // the data-zcb-ref attribute).
  const btnA2 = snap2.nodes.find((n: any) => n.selector?.includes("#btn-a"));
  check(
    !!btnA2 && btnA2.ref === btnARef,
    `#btn-a ref stable across snapshots (${btnARef} → ${btnA2?.ref})`,
  );

  // The new button got a ref.
  const dynBtn = snap2.nodes.find((n: any) => n.selector?.includes("#dyn-btn"));
  check(!!dynBtn, "snapshot #2 includes the dynamically inserted #dyn-btn");

  // Both refs must still be clickable (refMap → DOM resolution).
  const before = await page.evaluate("window.__aClicks || 0");
  const clickA = await invoke(page, "page_click", { ref: btnARef });
  check(!clickA.__error, "click #btn-a via its (stable) ref works");
  const after = await page.evaluate("window.__aClicks || 0");
  check(after === before + 1, `stable-ref click actually fired onclick (${before}→${after})`);

  const beforeDyn = await page.evaluate("window.__dynClicks || 0");
  const clickDyn = await invoke(page, "page_click", { ref: dynBtn.ref });
  check(!clickDyn.__error, "click #dyn-btn via its new ref works");
  const afterDyn = await page.evaluate("window.__dynClicks || 0");
  check(afterDyn === beforeDyn + 1, "new-ref click actually fired onclick");
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
