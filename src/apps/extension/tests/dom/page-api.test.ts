// The shared page API: single-source guarantees. The api is rebuilt from its
// OWN SOURCE TEXT (exactly what the CDP backend ships through
// Runtime.evaluate) and driven against happy-dom, so these tests prove
// self-containment - a reference to module scope would throw here just as it
// would in the page.

import { describe, expect, test } from "vitest";
import { pageApiExpression } from "@/lib/background/backends/cdp";
import { createPageApi, type PageApi, REF_ATTR } from "@/lib/dom/page-api";

// Rebuild the factory the way the page receives it: source text only.
function rebuiltApi(): PageApi {
  // eslint-disable-next-line no-new-func
  const factory = new Function(`return (${createPageApi.toString()});`)() as typeof createPageApi;
  return factory(REF_ATTR);
}

describe("self-containment", () => {
  test("the factory source references no module bindings", () => {
    const src = createPageApi.toString();
    expect(src).not.toContain("require(");
    expect(src).not.toContain("import(");
    // The stringified factory must not lean on esbuild/vite helper bindings.
    expect(src).not.toMatch(/__[a-zA-Z]+Helper/);
  });

  test("a source-rebuilt instance runs against the DOM", () => {
    document.body.innerHTML = `<button id="go" type="submit">Buy now</button>`;
    const api = rebuiltApi();
    const snap = api.snapshot();
    expect(snap.refCount).toBe(1);
    expect(snap.nodes[0]?.role).toBe("button");
    expect(snap.nodes[0]?.name).toBe("Buy now");
  });
});

describe("refs interoperate across instances (content <-> CDP)", () => {
  test("an element tagged by one instance resolves by attribute in a fresh one", () => {
    document.body.innerHTML = `<a id="l" href="https://example.com">Link</a>`;
    const first = createPageApi(REF_ATTR);
    const snap = first.snapshot();
    const ref = snap.nodes[0]?.ref;
    expect(ref).toBeDefined();
    // A brand-new instance (the CDP case: fresh evaluate per call) must
    // resolve the same ref via the DOM attribute.
    const second = rebuiltApi();
    const probe = second.probeClick({ ref });
    expect(probe.tagName).toBe("A");
    expect(probe.hasHref).toBe(true);
  });

  test("re-snapshot advances past reused refs so new elements never collide", () => {
    document.body.innerHTML = `<button id="b1">One</button>`;
    const api = createPageApi(REF_ATTR);
    api.snapshot();
    const b2 = document.createElement("button");
    b2.textContent = "Two";
    document.body.appendChild(b2);
    const snap = api.snapshot();
    const refs = snap.nodes.map((n) => n.ref);
    expect(new Set(refs).size).toBe(refs.length);
  });
});

describe("probe + act", () => {
  test("probeClick reports the risk-relevant descriptor without clicking", () => {
    document.body.innerHTML = `<button id="s" type="submit">Pay</button>`;
    let clicked = false;
    document.getElementById("s")?.addEventListener("click", () => {
      clicked = true;
    });
    const api = createPageApi(REF_ATTR);
    const probe = api.probeClick({ selector: "#s" });
    expect(probe).toEqual({
      tagName: "BUTTON",
      role: "button",
      type: "submit",
      hasHref: false,
      name: "Pay",
    });
    expect(clicked).toBe(false);
    api.click({ selector: "#s" });
    expect(clicked).toBe(true);
  });

  test("press dispatches keydown/keyup with parsed modifiers", () => {
    document.body.innerHTML = `<input id="i" />`;
    const input = document.getElementById("i") as HTMLInputElement;
    input.focus();
    const seen: Array<{ type: string; key: string; ctrl: boolean }> = [];
    input.addEventListener("keydown", (e) =>
      seen.push({ type: "keydown", key: e.key, ctrl: e.ctrlKey }),
    );
    input.addEventListener("keyup", (e) =>
      seen.push({ type: "keyup", key: e.key, ctrl: e.ctrlKey }),
    );
    const api = createPageApi(REF_ATTR);
    const out = api.press({ keys: "Control+A" });
    expect(out).toEqual({ pressed: "Control+A" });
    expect(seen).toEqual([
      { type: "keydown", key: "A", ctrl: true },
      { type: "keyup", key: "A", ctrl: true },
    ]);
  });

  test("click with `expect` refuses a target swapped behind the confirmation", () => {
    document.body.innerHTML = `<button id="s" type="submit">Pay $5</button>`;
    const api = createPageApi(REF_ATTR);
    const approved = api.probeClick({ selector: "#s" });
    // The page swaps what "#s" resolves to while the confirmation is open.
    document.body.innerHTML = `<button id="s" type="submit">Pay $5000</button>`;
    expect(() => api.click({ selector: "#s", expect: approved })).toThrow(
      "click target changed while the confirmation was open",
    );
    // Unchanged target still clicks.
    document.body.innerHTML = `<button id="s" type="submit">Pay $5</button>`;
    expect(api.click({ selector: "#s", expect: approved }).role).toBe("button");
  });

  test("press refuses an empty spec", () => {
    const api = createPageApi(REF_ATTR);
    expect(() => api.press({ keys: "  " })).toThrow("page_press needs `keys`");
  });

  test("readStorage returns RAW values (masking is the SW's job)", () => {
    // This happy-dom setup exposes no Web Storage; a minimal stub suffices -
    // the point under test is that NO masking happens page-side.
    const backing = new Map<string, string>([
      ["authToken", "super-secret-raw-value-1234567890abcdef"],
    ]);
    const stub = {
      getItem: (k: string) => backing.get(k) ?? null,
      key: (i: number) => [...backing.keys()][i] ?? null,
      get length() {
        return backing.size;
      },
    };
    Object.defineProperty(window, "localStorage", { configurable: true, value: stub });
    const api = createPageApi(REF_ATTR);
    const one = api.readStorage({ key: "authToken" });
    expect(one).toEqual({
      key: "authToken",
      found: true,
      value: "super-secret-raw-value-1234567890abcdef",
    });
  });
});

describe("pageApiExpression", () => {
  test("embeds the factory source, the ref attribute, and JSON args", () => {
    const expr = pageApiExpression("probeClick", [{ ref: "e1" }]);
    expect(expr).toContain("createTreeWalker");
    expect(expr).toContain(JSON.stringify(REF_ATTR));
    expect(expr).toContain('.probeClick({"ref":"e1"})');
  });

  test("args are JSON, never spliced code", () => {
    const expr = pageApiExpression("click", [{ selector: 'x");alert(1);//' }]);
    expect(expr).toContain(JSON.stringify({ selector: 'x");alert(1);//' }));
  });
});
