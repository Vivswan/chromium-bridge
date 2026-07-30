// The CDP backend's probeClick receive boundary: the MAIN-world eval result
// is parsed with ClickProbeSchema (fail closed) before it can feed the risk
// decision / confirmation / click binding, rather than being cast straight
// into authorization.

import { beforeEach, describe, expect, test, vi } from "vitest";
import { CdpBackend } from "@/lib/background/backends/cdp";
import { cdpRegistry } from "@/lib/background/cdp/registry";
import type { ResolvedTab } from "@/lib/background/tabs";

const TAB = { id: 7, url: "https://example.com/x" } as ResolvedTab;
const PROBE = { tagName: "BUTTON", role: "button", type: "submit", hasHref: false, name: "Pay" };

function fakeSession(evalResult: unknown) {
  return { evaluate: vi.fn(async () => evalResult) };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("CdpBackend.probeClick parses the probe at the receive boundary", () => {
  test("a conforming probe is returned", async () => {
    vi.spyOn(cdpRegistry, "get").mockResolvedValue(
      fakeSession(PROBE) as unknown as Awaited<ReturnType<typeof cdpRegistry.get>>,
    );
    await expect(new CdpBackend().probeClick({ selector: "#s" }, TAB)).resolves.toEqual(PROBE);
  });

  test("an adversarial probe shape is refused, never fed into authorization", async () => {
    for (const bad of [
      { tagName: "BUTTON", role: "button" }, // missing risk-relevant fields
      { tagName: "BUTTON", role: "button", type: "submit", hasHref: "no", name: "x" },
      42,
      null,
    ]) {
      vi.spyOn(cdpRegistry, "get").mockResolvedValue(
        fakeSession(bad) as unknown as Awaited<ReturnType<typeof cdpRegistry.get>>,
      );
      await expect(new CdpBackend().probeClick({ selector: "#s" }, TAB)).rejects.toThrow(
        "not a valid descriptor",
      );
    }
  });
});
