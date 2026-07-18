// The confirm window's panic exit (ADR-0030): confirm_deny_kill denies every
// pending confirmation AND engages the kill switch in one SW-side step. The
// property that must hold under any interleaving: by the time the kill_engage
// frame is posted to the host, the in-flight action is ALREADY settled false,
// so nothing arriving later (a window Allow, a hardware tap's verdict) can
// approve it - and while the engage is in flight, no OTHER confirmation
// (queued or newly arriving) is presented for approval. Sender gating rides
// the same confirm-window-only rule as the other confirm_* messages.

import type { ConfirmPayload } from "@chromium-bridge/shared";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing";
import { resetAuditForTests } from "@/lib/background/audit-log";
import type { Presentation } from "@/lib/background/confirm/service";
import {
  confirmWithUser,
  installConfirmationProvider,
  installPresenceProvider,
  releasePanicDeny,
  resolveConfirm,
} from "@/lib/background/confirm/service";
import {
  attachPort,
  handleKillFrame,
  requestKillStatus,
  resetKillForTests,
} from "@/lib/background/kill";
import { route } from "@/lib/background/messages";

const EXT_ID = "test-ext-id";

const confirmSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/confirm.html?id=x`,
} as Browser.runtime.MessageSender;
const optionsSender = {
  id: EXT_ID,
  url: `chrome-extension://${EXT_ID}/options.html`,
} as Browser.runtime.MessageSender;

interface FakePresentation extends Presentation {
  payload: ConfirmPayload;
  dismissed: boolean;
  approve: () => void;
}

function fakeProvider(install: (p: Parameters<typeof installConfirmationProvider>[0]) => void) {
  const presented: FakePresentation[] = [];
  install({
    present(payload) {
      let approve!: () => void;
      const verdict = new Promise<boolean>((resolve) => {
        approve = () => resolve(true);
      });
      const p: FakePresentation = {
        payload,
        verdict,
        approve,
        dismissed: false,
        dismiss() {
          p.dismissed = true;
        },
      };
      presented.push(p);
      return p;
    },
  });
  return presented;
}

const REQ = {
  kind: "eval" as const,
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return 1;",
  timeoutMs: 5000,
};

// installPresenceProvider has no uninstall (module state), so tests that want
// the DEFAULT window provider use a kind presence never routes.
const WINDOW_REQ = { ...REQ, kind: "click" as const };

beforeEach(() => {
  fakeBrowser.reset();
  (fakeBrowser.runtime as unknown as Record<string, unknown>).id = EXT_ID;
  resetKillForTests();
  resetAuditForTests();
  releasePanicDeny();
  vi.useFakeTimers();
});

afterEach(async () => {
  await vi.runAllTimersAsync();
  vi.useRealTimers();
  resetKillForTests();
  releasePanicDeny();
});

describe("confirm_deny_kill", () => {
  test("denies first: when the kill frame is posted, the op is already settled", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const verdict = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    const shown = presented[0];
    expect(shown).toBeDefined();
    const id = shown!.payload.id;

    // The proof lives INSIDE the port: at the exact moment the SW posts
    // kill_engage, an approval for the confirmation must already be
    // impossible. If the deny were reordered after the engage, this
    // resolveConfirm(true) would succeed and the test would fail loudly.
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      expect(resolveConfirm(id, true)).toEqual({
        ok: false,
        error: "no such pending confirmation",
      });
      return true;
    });

    const response = new Promise<unknown>((resolve) => {
      route({ type: "confirm_deny_kill" }, confirmSender, resolve);
    });
    await expect(verdict).resolves.toBe(false);
    expect(shown!.dismissed).toBe(true);
    expect(frames).toEqual([{ type: "kill_engage" }]);

    // The host answers; the relay reports the resulting killed state.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const view = (await response) as { ok: boolean; state?: string };
    expect(view.ok).toBe(true);
    expect(view.state).toBe("killed");
  });

  test("queued and newly arriving confirmations are denied unseen while the engage is in flight", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const first = confirmWithUser(WINDOW_REQ);
    const queued = confirmWithUser(WINDOW_REQ); // waits behind the first
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);

    attachPort(() => true); // engage posted; the host has not answered yet
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await expect(first).resolves.toBe(false);
    // The queued request drains through the latch without ever presenting a
    // surface the user could approve.
    await expect(queued).resolves.toBe(false);
    expect(presented).toHaveLength(1);

    // A request arriving while the engage is still in flight: denied unseen.
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(1);

    // Once the host answers the engage, the latch lifts and confirmations
    // present normally again (the mirror gate, not this latch, is what
    // refuses ops while killed - killGate has its own suite).
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(2);
    resolveConfirm(presented[1]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a hardware-gated confirmation is denied and a late tap verdict cannot flip it", async () => {
    const presented = fakeProvider((p) => installPresenceProvider(p, async () => true));
    const verdict = confirmWithUser(REQ); // eval routes to the presence provider
    await vi.advanceTimersByTimeAsync(0);
    const shown = presented[0];
    expect(shown?.payload.hardware).toBe(true);

    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await expect(verdict).resolves.toBe(false);
    expect(shown!.dismissed).toBe(true);

    // The Touch ID prompt's signed approval lands AFTER the panic: the
    // settle is single-use, so the late verdict changes nothing.
    shown!.approve();
    await vi.advanceTimersByTimeAsync(0);
    await expect(verdict).resolves.toBe(false);
  });

  test("the engage is not refused while another kill exchange holds the slot, and the latch holds until the host confirms", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    void requestKillStatus(); // occupies the single request slot, unanswered
    const response = new Promise<unknown>((resolve) => {
      route({ type: "confirm_deny_kill" }, confirmSender, resolve);
    });
    // The panic engage is posted anyway - the brake beats bookkeeping - and
    // the response reports only the send outcome.
    expect(frames).toEqual([{ type: "kill_status" }, { type: "kill_engage" }]);
    expect(((await response) as { ok: boolean }).ok).toBe(true);

    // The response resolving must NOT lift the latch: the host has not
    // answered the engage. Even the earlier status query answering "alive"
    // keeps it latched - only a refusing mirror state lifts it.
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);

    // The engage's answer flips the mirror to killed: the latch lifts (the
    // request gate refuses upstream from here on).
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    const after = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1); // presented again: the latch lifted
    expect(resolveConfirm(presented[0]!.payload.id, false).ok).toBe(true);
    await expect(after).resolves.toBe(false);
  });

  test("a confirmation mid-provider-selection when the panic lands is denied unseen", async () => {
    // The panic can land while providerFor is awaiting the presence-routing
    // predicate: `active` is not yet registered, so the deny-all cannot
    // settle it - the post-selection latch recheck must catch it instead.
    let releaseEnabled!: (v: boolean) => void;
    const enabledGate = new Promise<boolean>((r) => {
      releaseEnabled = r;
    });
    const presented = fakeProvider((p) => installPresenceProvider(p, () => enabledGate));
    const verdict = confirmWithUser(REQ); // eval routes through the predicate
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(0); // still selecting a provider

    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    releaseEnabled(true);
    await expect(verdict).resolves.toBe(false);
    expect(presented).toHaveLength(0); // never presented, nothing to approve
  });

  test("mid-selection denial survives the latch lifting before selection completes", async () => {
    // Harder interleaving: the kill CONFIRMS (mirror killed, latch lifted)
    // while provider selection is still awaited. The level check alone would
    // present the pre-panic request; the epoch marker must deny it.
    let releaseEnabled!: (v: boolean) => void;
    const enabledGate = new Promise<boolean>((r) => {
      releaseEnabled = r;
    });
    const presented = fakeProvider((p) => installPresenceProvider(p, () => enabledGate));
    const verdict = confirmWithUser(REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(0);

    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    // The host confirms the engage BEFORE selection completes: latch lifts.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);

    releaseEnabled(true);
    await expect(verdict).resolves.toBe(false);
    expect(presented).toHaveLength(0); // the panic crossed its window: denied
  });

  test("a request QUEUED behind a mid-selection one when the panic lands is denied too", async () => {
    // A is mid-selection (no active entry to settle), B waits in the queue.
    // The panic fires and the latch lifts before A's selection completes: A
    // denies on its epoch, and B - created before the panic - must deny on
    // ITS request-time epoch rather than present into the lifted latch.
    const presentedDefault = fakeProvider(installConfirmationProvider);
    let releaseEnabled!: (v: boolean) => void;
    const enabledGate = new Promise<boolean>((r) => {
      releaseEnabled = r;
    });
    const presentedHw = fakeProvider((p) => installPresenceProvider(p, () => enabledGate));

    const a = confirmWithUser(REQ); // presence route: parked in selection
    const b = confirmWithUser(WINDOW_REQ); // queued behind A, pre-panic
    await vi.advanceTimersByTimeAsync(0);
    expect(presentedHw).toHaveLength(0);
    expect(presentedDefault).toHaveLength(0);

    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    // Created WHILE the latch is on, behind the still-selecting A: must be
    // denied at the door, not parked in the queue where a lifted latch (and
    // its own post-panic epoch) would let it present.
    const c = confirmWithUser(WINDOW_REQ);
    await expect(c).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0); // latch lifted before A completes

    releaseEnabled(true);
    await expect(a).resolves.toBe(false);
    await expect(b).resolves.toBe(false);
    expect(presentedHw).toHaveLength(0);
    expect(presentedDefault).toHaveLength(0);

    // A request created AFTER the panic settled presents normally.
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presentedDefault).toHaveLength(1);
    resolveConfirm(presentedDefault[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("with nothing pending it still engages (capability reduction)", async () => {
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    expect(frames).toEqual([{ type: "kill_engage" }]);
  });

  test("refused senders neither deny nor engage", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const verdict = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    const id = presented[0]!.payload.id;

    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });

    // An extension page that is NOT the confirm window: confirm-window-only.
    const fromOptions = new Promise<unknown>((resolve) => {
      route({ type: "confirm_deny_kill" }, optionsSender, resolve);
    });
    await expect(fromOptions).resolves.toEqual({
      ok: false,
      error: "confirmations are confirm-window-only",
    });
    expect(frames).toEqual([]);

    // The confirmation is still pending and still answerable.
    expect(resolveConfirm(id, false).ok).toBe(true);
    await expect(verdict).resolves.toBe(false);
  });
});
