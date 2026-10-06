// The audit panel's render path over the SW contract: this browser's ring and the host trail render as two
// labelled lists, the host list showing the host's own words per line (kind and fields) with the timestamp
// localized; an unreadable host trail renders the host's error, never an empty healthy-looking list; an empty
// trail renders the CLI's empty state with the path the host looked in; Refresh re-asks the host alone.

import type { AuditEntry } from "@chromium-bridge/shared/enclave";
import type { AuditTrailEntry } from "@chromium-bridge/shared/envelope.gen";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

const RING: AuditEntry[] = [{ at: 1_700_000_000_000, kind: "confirm_denied", tool: "page_eval" }];

const TRAIL: AuditTrailEntry[] = [
  { entry: "record", ts_ms: 3000, kind: "pair_client", fields: "surface=cli outcome=ok" },
  { entry: "unrecognized", text: "UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)" },
  { entry: "record", ts_ms: 2000, kind: "kill_release", fields: "" },
];

type HostReply =
  | { ok: true; entries: AuditTrailEntry[]; older: number; path: string }
  | { ok: false; error: string };

let sent: Array<{ type: string }>;
let hostReply: () => HostReply;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  hostReply = () => ({ ok: true, entries: TRAIL, older: 1, path: "/run/user/1000/audit.log" });
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  const EN = {
    audit_desc: { message: "Recent security decisions." },
    audit_browser_title: { message: "This browser" },
    audit_empty: { message: "No audit events recorded yet." },
    audit_kind_confirm_denied: { message: "Confirmation denied" },
    audit_host_title: { message: "Host trail" },
    audit_host_desc: { message: "The host's audit.log." },
    audit_refresh: { message: "Refresh" },
    audit_host_loading: { message: "Loading..." },
    audit_host_error: { message: "Could not read the host trail: $1" },
    audit_host_empty: { message: "no audit records yet (looked in $1)" },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: "get_audit" | "get_host_audit" };
    sent.push(m);
    return m.type === "get_audit" ? { ok: true, entries: RING } : hostReply();
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { AuditPanel } = await import("@/entrypoints/options/AuditPanel");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  return render(<AuditPanel />);
}

describe("AuditPanel", () => {
  test("renders the ring and the host trail as two labelled lists, the host's words per line", async () => {
    await mount();
    await screen.findByText("pair_client");
    expect(screen.getByText("This browser")).toBeInTheDocument();
    expect(screen.getByText("Host trail")).toBeInTheDocument();
    expect(screen.getByText("Confirmation denied")).toBeInTheDocument();
    // The fields exactly as the CLI spells them, the kind as its wire name.
    expect(screen.getByText("surface=cli outcome=ok")).toBeInTheDocument();
    expect(screen.getByText("kill_release")).toBeInTheDocument();
    expect(
      screen.getByText("UNRECOGNIZED RECORD (corrupt, tampered, or newer schema)"),
    ).toBeInTheDocument();
    // The host list is newest first, as the host sends it; the unparsable line keeps its position.
    const items = screen.getAllByRole("listitem").map((li) => li.textContent ?? "");
    const trail = items.filter((text) => !text.includes("Confirmation denied"));
    expect(trail.map((text) => text.includes("pair_client"))).toEqual([true, false, false]);
    expect(sent).toEqual([{ type: "get_audit" }, { type: "get_host_audit" }]);
  });

  test("an unreadable host trail renders the host's error and no host lines", async () => {
    hostReply = () => ({ ok: false, error: "native host not connected" });
    await mount();
    await screen.findByText("Could not read the host trail: native host not connected");
    expect(screen.queryByText("pair_client")).toBeNull();
    // The browser ring still renders: the two lists fail independently.
    expect(screen.getByText("Confirmation denied")).toBeInTheDocument();
  });

  test("an empty trail renders the empty state with the path the host looked in, not a bare list", async () => {
    hostReply = () => ({ ok: true, entries: [], older: 0, path: "/run/user/1000/audit.log" });
    await mount();
    await screen.findByText("no audit records yet (looked in /run/user/1000/audit.log)");
  });

  test("Refresh re-asks the host trail alone", async () => {
    await mount();
    await screen.findByText("pair_client");
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(sent).toEqual([
      { type: "get_audit" },
      { type: "get_host_audit" },
      { type: "get_host_audit" },
    ]);
  });
});
