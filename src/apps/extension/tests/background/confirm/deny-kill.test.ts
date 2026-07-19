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
  denyAllConfirmations,
  installConfirmationProvider,
  installPresenceProvider,
  releasePanicDeny,
  resetPanicForTests,
  resolveConfirm,
} from "@/lib/background/confirm/service";
import {
  attachPort,
  detachPort,
  handleKillFrame,
  requestKillStatus,
  resetKillForTests,
  setKillSwitch,
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
  resetPanicForTests();
  vi.useFakeTimers();
});

afterEach(async () => {
  await vi.runAllTimersAsync();
  vi.useRealTimers();
  resetKillForTests();
  resetPanicForTests();
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

    // The host confirming the engage does NOT lift the latch: while killed,
    // the mirror gate refuses ops upstream anyway, and the latch waits for
    // the state to authoritatively read alive again - the explicit,
    // presence-gated release - before confirmations may present.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(1);

    // The user releases the switch: alive after the refusal. The latch
    // lifts and confirmations present normally again.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
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
    // keeps it latched - an alive that precedes any refusal proves nothing
    // about the engage still queued on the pipe.
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);

    // The engage's answer flips the mirror to killed - the refusal applied
    // (the request gate refuses upstream from here on), but the latch still
    // holds: it lifts only when the state reads alive AFTER that refusal.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The explicit release lands: alive after the refusal lifts the latch.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
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
    // Harder interleaving: the kill CONFIRMS and is then explicitly
    // RELEASED (mirror killed, then alive: latch lifted) while provider
    // selection is still awaited. The level check alone would present the
    // pre-panic request; the epoch marker must deny it.
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
    // The engage confirms AND the user releases BEFORE selection completes:
    // the latch lifts.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
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
    // The engage confirms and the user releases: latch lifted before A's
    // selection completes.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);

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

  test("panic during a pending release: the stale killed mirror must not lift the latch", async () => {
    // The switch is engaged (mirror reads killed) and a presence-gated
    // release is in flight. The panic lands: the mirror still reads the
    // STALE killed while the host is about to answer the release with
    // alive - and the panic's engage is queued BEHIND that release on the
    // pipe. Lifting from the mirror snapshot would open a window (release
    // answered alive, engage not yet applied) where a fresh confirmation
    // presents against an open gate.
    const presented = fakeProvider(installConfirmationProvider);
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    void setKillSwitch(false); // the release occupies the slot, unanswered
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    expect(frames).toEqual([{ type: "kill_release" }, { type: "kill_engage" }]);
    await vi.advanceTimersByTimeAsync(0);

    // The release's answer lands: alive. The request gate is OPEN upstream
    // and the engage is still queued - the latch must hold.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The engage applies (killed), then a later explicit release (alive):
    // only THAT alive - ordered after the refusal - lifts the latch.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("an engage TIMEOUT leaves the latch down: the posted frame may still apply", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => true); // the post succeeds; the host never answers
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    // Past the request budget: the exchange reports ok:false (timed out),
    // but the frame is ON the pipe and the host may still apply it. A lift
    // here would let a confirmation present right as the kill lands.
    await vi.advanceTimersByTimeAsync(11_000);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("an engage SEND FAILURE lifts the latch: nothing is in flight", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => false); // the post itself fails
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    // Nothing reached the pipe: the mirror tells the user the truth and
    // bricking every future confirmation would help no one.
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a stale release from an earlier panic cannot lift a newer panic's latch", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    // Panic 1's engage fails to SEND (scheduling its epoch-scoped lift);
    // panic 2's engage posts fine and is still in flight when that stale
    // lift runs.
    let posts = 0;
    attachPort(() => {
      posts += 1;
      return posts > 1;
    });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    // Panic 1's send-failure release has run by now; it must be a no-op
    // against panic 2's still-armed latch.
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("releasePanicDeny is epoch-scoped (unit)", async () => {
    const first = denyAllConfirmations();
    const second = denyAllConfirmations();
    releasePanicDeny(first); // stale: must not lift the newer latch
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    releasePanicDeny(second);
    const presented = fakeProvider(installConfirmationProvider);
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a pre-panic killed frame mid-write cannot serve as the panic's refusal proof", async () => {
    // A killed frame ARRIVES (a cross-surface engage push, or a stale status
    // answer) and its serialized mirror write is still in flight when the
    // panic lands. It must not count as the panic's phase-1 refusal: the
    // only refusal seen predates the engage, so a pre-panic release's alive
    // answer arriving next would otherwise lift the latch with the engage
    // still queued behind the release.
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => true);
    void setKillSwitch(false); // pre-panic release occupies the slot
    const preKilled = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {}); // same tick
    await preKilled;
    await vi.advanceTimersByTimeAsync(0);

    // The pre-panic release answers alive: the latch must hold.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The engage's own refusal, then an explicit release: now it lifts.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a port disconnect after the engage was posted must not lift the latch", async () => {
    // The pending exchange fails on disconnect, but its frame WAS handed to
    // the port - the host may have applied it before dying. Maybe-sent is
    // not never-sent: the latch stays down.
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    detachPort();
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("an unconfirmed engage is re-posted on the fresh port (at-least-once brake)", async () => {
    // The engage was posted and the host died before any refusing frame
    // arrived: the reconnect must re-assert the brake, so a dying host
    // cannot swallow an acknowledged kill.
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    detachPort();
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    expect(frames).toEqual([{ type: "kill_engage" }]);

    // Once a refusing frame confirms the brake applied, a further reconnect
    // must NOT re-post - the engage is settled.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    const afterConfirm: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      afterConfirm.push(frame as Record<string, unknown>);
      return true;
    });
    expect(afterConfirm).toEqual([]);
  });

  test("a failed second panic cannot lift while the first panic's engage is outstanding", async () => {
    // "My send failed" is not proof that no engage is in flight globally:
    // panic 1's engage reached the pipe and may still apply, so panic 2's
    // send failure must leave the latch down until the kill settles.
    const presented = fakeProvider(installConfirmationProvider);
    let posts = 0;
    attachPort(() => {
      posts += 1;
      return posts === 1; // panic 1 reaches the pipe; panic 2's post fails
    });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("a failed repeat panic lifts once the outstanding engage settles and is released", async () => {
    // Liveness twin of the test above: panic A's engage is on the pipe and
    // its refusing REPLY has arrived (mirror write still in flight) when
    // panic B lands and B's own post fails. B's waiter must anchor at the
    // outstanding engage - A's settlement is exactly the brake B wants - so
    // the kill confirming and the later explicit release still lift the
    // latch instead of denying confirmations until the SW dies.
    const presented = fakeProvider(installConfirmationProvider);
    let posts = 0;
    attachPort(() => {
      posts += 1;
      return posts === 1;
    });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {}); // panic A
    const refusal = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {}); // panic B, send fails
    await refusal;
    await vi.advanceTimersByTimeAsync(0);
    // Still latched while killed (the mirror gate refuses upstream anyway).
    await expect(confirmWithUser(WINDOW_REQ)).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The explicit presence-gated release settles everything: the latch
    // lifts - a send-failure repeat panic must not brick confirmations.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ);
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
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
