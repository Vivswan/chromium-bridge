// The host-pairing block's render path over the SW contract for the host key line: beside the extension's
// own pin state, the block shows where the host key lives in the host's words (the `key:` line of
// `chromium-bridge enclave-status`), and shows no key line when the host report is unreadable, so the page
// never guesses a store the host did not name.

import type { HealthReport } from "@chromium-bridge/shared/envelope.gen";
import type { RuntimeResponse } from "@chromium-bridge/shared/runtime-msg";
import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

const REPORT: HealthReport = {
  version: "1.2.3",
  platform: "linux/x86_64",
  lock_file: { value: "/run/user/1000/chromium-bridge/run.lock", details: [] },
  mcp_server: { value: "not probed (no lock file)", details: [] },
  kill_switch: { value: "off (bridge activity permitted)", details: [] },
  policy_baseline: { value: "revision 3, unsigned", details: [] },
  host_key: "present (com.example.key, file (host_key.json))",
  summary: "server not running - is your MCP client started?",
  healthy: false,
};

const PINNED = {
  ok: true,
  state: "pinned",
  blocked: false,
  keyId: "ab".repeat(32),
  fingerprint: "ABCD EFGH",
  pinnedAt: 1_700_000_000_000,
};

type DoctorReply = RuntimeResponse<"get_doctor">;

let doctorReply: () => DoctorReply;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  doctorReply = () => ({ ok: true, report: REPORT });
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  const EN = {
    enroll_loading: { message: "Loading..." },
    enroll_state_pinned: { message: "Paired - the host's public key is pinned." },
    enroll_pinned_at: { message: "Pinned at $1" },
    enroll_never_verified: { message: "Not manually verified yet" },
    enroll_btn_verify: { message: "Verify now" },
    enroll_btn_revoke: { message: "Unpair" },
    enroll_host_key_line: { message: "Host key: $1" },
    enroll_no_status: { message: "Could not read the pairing status." },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: "get_enrollment" | "get_doctor" };
    return m.type === "get_enrollment" ? PINNED : doctorReply();
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { HostPairing } = await import("@/entrypoints/options/HostPairing");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  return render(<HostPairing />);
}

describe("HostPairing host key line", () => {
  test("shows where the host key lives, in the host's words, beside the pin", async () => {
    await mount();
    await screen.findByText("Host key: present (com.example.key, file (host_key.json))");
    expect(screen.getByText("Paired - the host's public key is pinned.")).toBeInTheDocument();
  });

  test("shows no key line when the host report is unreadable", async () => {
    doctorReply = () => ({ ok: false, error: "native host not connected" });
    await mount();
    await screen.findByText("Paired - the host's public key is pinned.");
    expect(screen.queryByText(/Host key:/)).toBeNull();
  });
});
