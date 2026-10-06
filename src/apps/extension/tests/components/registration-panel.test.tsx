// The registration panel's render path over the SW contract: the rows the host reports render with their state
// and location, a repair posts repair_registration and shows the post-repair rows, an undetected row alone
// offers a register action that names its browser, a failed repair shows the host's error and re-asks for the
// rows, and a not-connected worker renders the refusal with the repair disabled, never an empty
// healthy-looking table. While a status read is outstanding both actions are disabled,
// since status and repair share one worker slot and a repair sent then is refused as already in flight.

import type { RegistrationRow } from "@chromium-bridge/shared/envelope.gen";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";

const ROWS: RegistrationRow[] = [
  {
    browser: "chrome",
    detected: true,
    state: { kind: "ok" },
    location: "/home/user/.config/google-chrome/NativeMessagingHosts/host.json",
  },
  {
    browser: "brave",
    detected: true,
    state: { kind: "stale", detail: "launch path missing" },
    location: "/home/user/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/host.json",
  },
  {
    browser: "edge",
    detected: false,
    state: { kind: "missing" },
    location: "/home/user/.config/microsoft-edge/NativeMessagingHosts/host.json",
  },
];

type Reply = { ok: true; browsers: RegistrationRow[] } | { ok: false; error: string };

let sent: Array<{ type: string; browsers?: string[] }>;
let replies: Record<"get_registration" | "repair_registration", () => Reply | Promise<Reply>>;

beforeEach(() => {
  fakeBrowser.reset();
  vi.resetModules();
  sent = [];
  replies = {
    get_registration: () => ({ ok: true, browsers: ROWS }),
    repair_registration: () => ({ ok: true, browsers: ROWS }),
  };
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getUILanguage = () => "en-US";
  (fakeBrowser.i18n as unknown as Record<string, unknown>).getMessage = () => "";
  const EN = {
    registration_desc: { message: "Where each browser looks for this host." },
    registration_refresh: { message: "Refresh" },
    registration_repair: { message: "Repair registrations" },
    registration_loading: { message: "Loading..." },
    registration_error: { message: "Could not read the registrations: $1" },
    registration_repair_failed: { message: "Repair failed: $1" },
    registration_detected: { message: "detected" },
    registration_not_detected: { message: "not detected" },
    registration_state_ok: { message: "ok" },
    registration_state_missing: { message: "missing" },
    registration_state_stale: { message: "stale" },
    registration_state_foreign: { message: "not ours" },
    registration_state_unreadable: { message: "unreadable" },
    registration_empty: { message: "The host knows no browser on this platform." },
    registration_restart_note: { message: "After a repair, restart the browser." },
    registration_register_one: { message: "Register $1" },
    registration_cli_only_note: {
      message: "Directory and machine-wide registration stay in the terminal.",
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({ ok: true, json: async () => EN }) as Response),
  );
  vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(async (msg: unknown) => {
    const m = msg as { type: keyof typeof replies };
    sent.push(m);
    return replies[m.type]();
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function mount() {
  const { RegistrationPanel } = await import("@/entrypoints/options/RegistrationPanel");
  const { initI18n } = await import("@/lib/i18n");
  await initI18n();
  return render(<RegistrationPanel />);
}

describe("RegistrationPanel", () => {
  test("renders every row with its browser, detection, state, detail, and location", async () => {
    await mount();
    await screen.findByText("chrome");
    expect(screen.getByText("brave")).toBeInTheDocument();
    expect(screen.getAllByText("detected")).toHaveLength(2);
    expect(screen.getByText("ok")).toBeInTheDocument();
    expect(screen.getByText("stale")).toBeInTheDocument();
    expect(screen.getByText("launch path missing")).toBeInTheDocument();
    expect(screen.getByText(ROWS[1]?.location ?? "")).toBeInTheDocument();
    expect(sent).toEqual([{ type: "get_registration" }]);
  });

  test("repair posts repair_registration and shows the post-repair rows", async () => {
    replies.repair_registration = () => ({
      ok: true,
      browsers: ROWS.map((row) => ({ ...row, state: { kind: "ok" } })),
    });
    await mount();
    await screen.findByText("stale");
    await userEvent.click(screen.getByRole("button", { name: "Repair registrations" }));
    await waitFor(() => expect(screen.getAllByText("ok")).toHaveLength(ROWS.length));
    expect(screen.queryByText("stale")).toBeNull();
    expect(sent).toEqual([{ type: "get_registration" }, { type: "repair_registration" }]);
  });

  test("an undetected row alone offers a register action, which names that browser", async () => {
    await mount();
    await screen.findByText("edge");
    expect(screen.getAllByRole("button", { name: /^Register / })).toHaveLength(1);
    await userEvent.click(screen.getByRole("button", { name: "Register edge" }));
    await waitFor(() =>
      expect(sent).toEqual([
        { type: "get_registration" },
        { type: "repair_registration", browsers: ["edge"] },
      ]),
    );
  });

  test("a failed repair shows the host's error and re-asks for the rows", async () => {
    replies.repair_registration = () => ({ ok: false, error: "brave: permission denied" });
    await mount();
    await screen.findByText("stale");
    await userEvent.click(screen.getByRole("button", { name: "Repair registrations" }));
    await screen.findByText("Repair failed: brave: permission denied");
    expect(sent).toEqual([
      { type: "get_registration" },
      { type: "repair_registration" },
      { type: "get_registration" },
    ]);
    // The rows shown are the re-read ones, never a table the failed repair left unvouched.
    expect(screen.getByText("stale")).toBeInTheDocument();
  });

  test("a not-connected worker renders the refusal and disables the repair", async () => {
    replies.get_registration = () => ({ ok: false, error: "native host not connected" });
    await mount();
    await screen.findByText("Could not read the registrations: native host not connected");
    expect(screen.getByRole("button", { name: "Repair registrations" })).toBeDisabled();
    expect(screen.queryByText("ok")).toBeNull();
  });

  test("while a refresh is outstanding both actions are disabled, so a repair cannot be refused as in flight", async () => {
    await mount();
    await screen.findByText("chrome");
    let release!: (reply: Reply) => void;
    replies.get_registration = () =>
      new Promise<Reply>((resolve) => {
        release = resolve;
      });
    await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
    const repair = screen.getByRole("button", { name: "Repair registrations" });
    expect(repair).toBeDisabled();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeDisabled();
    await userEvent.click(repair);
    expect(sent).toEqual([{ type: "get_registration" }, { type: "get_registration" }]);
    release({ ok: true, browsers: ROWS });
    await waitFor(() => expect(repair).toBeEnabled());
  });
});
