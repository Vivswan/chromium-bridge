// The confirm window's panic exit (ADR-0030): confirm_deny_kill denies every
// pending confirmation AND engages the kill switch in one SW-side step. The
// property that must hold under any interleaving: by the time the kill_engage
// frame is posted to the host, the in-flight action is ALREADY settled false,
// so nothing arriving later (a window Allow, a hardware tap's verdict) can
// approve it - and while the engage is in flight, no OTHER confirmation
// (queued or newly arriving) is presented for approval. Sender gating rides
// the same confirm-window-only rule as the other confirm_* messages.

import { type ConfirmPayload, isHardwareGated } from "@chromium-bridge/shared";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import type { Browser } from "wxt/browser";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { readRing, resetAuditForTests } from "@/lib/background/audit-log";
import type { Presentation } from "@/lib/background/confirm/service";
import {
  confirmWithUser,
  currentPanicEpoch,
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

// Requests are minted per call: panicEpoch is the DECISION-START capture
// (SFX-2), so a static literal would go stale the moment any test panics.
const REQ = () => ({
  kind: "eval" as const,
  origin: "https://example.com",
  tabTitle: "Example",
  detail: "return 1;",
  timeoutMs: 5000,
  // The decision-time routing verdict (ADR-0032 decision 4): eval routes to
  // the presence provider whenever one is installed.
  presenceRouting: true,
  panicEpoch: currentPanicEpoch(),
});

// installPresenceProvider has no uninstall (module state), so tests that want
// the DEFAULT window provider use a kind presence never routes.
const WINDOW_REQ = () => ({ ...REQ(), kind: "click" as const, presenceRouting: false });

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
    const verdict = confirmWithUser(WINDOW_REQ());
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
    const first = confirmWithUser(WINDOW_REQ());
    const queued = confirmWithUser(WINDOW_REQ()); // waits behind the first
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(1);

    // The host confirming the engage does NOT lift the latch: while killed,
    // the mirror gate refuses ops upstream anyway, and the latch waits for
    // the state to authoritatively read alive again - the explicit,
    // presence-gated release - before confirmations may present.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(1);

    // The user releases the switch: alive after the refusal. The latch
    // lifts and confirmations present normally again.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(2);
    resolveConfirm(presented[1]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a hardware-gated confirmation is denied and a late tap verdict cannot flip it", async () => {
    const presented = fakeProvider((p) => installPresenceProvider(p));
    const verdict = confirmWithUser(REQ()); // eval routes to the presence provider
    await vi.advanceTimersByTimeAsync(0);
    const shown = presented[0];
    expect(shown && isHardwareGated(shown.payload)).toBe(true);

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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);

    // The engage's answer flips the mirror to killed - the refusal applied
    // (the request gate refuses upstream from here on), but the latch still
    // holds: it lifts only when the state reads alive AFTER that refusal.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The explicit release lands: alive after the refusal lifts the latch.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const after = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1); // presented again: the latch lifted
    expect(resolveConfirm(presented[0]!.payload.id, false).ok).toBe(true);
    await expect(after).resolves.toBe(false);
  });

  // The panic-window awaits moved OUT of the service with SFX-2: provider
  // selection is synchronous (providerFor consumes the request's
  // decision-time presenceRouting verdict), but the DECISION's own awaits -
  // the presence routing probe in gate.ts/upload.ts, the click probe -
  // precede confirmWithUser. The requests below carry an epoch captured at
  // decision start (currentPanicEpoch), so the three properties the old
  // parked-predicate tests pinned hold in the new model.

  test("a panic landing during a decision's pre-confirmation await denies its confirmation unseen", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    // Decision start: the epoch is captured BEFORE the decision's first
    // await (the caller-side routing probe stands in for it here).
    const decisionEpoch = currentPanicEpoch();
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {}); // the panic lands mid-await
    const verdict = confirmWithUser({ ...WINDOW_REQ(), panicEpoch: decisionEpoch });
    await vi.advanceTimersByTimeAsync(0);
    await expect(verdict).resolves.toBe(false);
    expect(presented).toHaveLength(0); // never presented, nothing to approve
  });

  test("that denial survives the latch lifting before the confirmation is even created", async () => {
    // Harder interleaving: the kill CONFIRMS and is then explicitly RELEASED
    // (mirror killed, then alive: latch lifted) while the decision is still
    // inside its pre-confirmation await. The level check alone would present
    // the pre-panic decision's confirmation; the decision-start epoch must
    // deny it.
    const presented = fakeProvider(installConfirmationProvider);
    const decisionEpoch = currentPanicEpoch();
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const verdict = confirmWithUser({ ...WINDOW_REQ(), panicEpoch: decisionEpoch });
    await vi.advanceTimersByTimeAsync(0);
    await expect(verdict).resolves.toBe(false);
    expect(presented).toHaveLength(0); // the panic crossed the decision: denied
  });

  test("a decision queued behind a mid-await one is denied too; a post-panic decision presents", async () => {
    // A holds the surface, B's decision has started (epoch captured) but its
    // confirmation is not created yet; the panic settles A and then lifts
    // before B reaches the service. B must deny on ITS decision-start epoch;
    // a decision started AFTER the panic presents normally.
    const presented = fakeProvider(installConfirmationProvider);
    const a = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    const bEpoch = currentPanicEpoch(); // B's decision start, pre-panic
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await expect(a).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const b = confirmWithUser({ ...WINDOW_REQ(), panicEpoch: bEpoch });
    await vi.advanceTimersByTimeAsync(0);
    await expect(b).resolves.toBe(false);
    expect(presented).toHaveLength(1); // B never presented

    const later = confirmWithUser(WINDOW_REQ()); // fresh decision, current epoch
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(2);
    resolveConfirm(presented[1]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("panic during a pending exchange answering alive: the stale killed mirror must not lift the latch", async () => {
    // The switch is engaged (mirror reads killed) and another exchange (a
    // status query here; a host-side app/CLI release poses the identical
    // race - the extension itself can no longer emit kill_release,
    // ADR-0032 decision 6) is in flight. The panic lands: the mirror still
    // reads the STALE killed while the host is about to answer that
    // exchange with alive - and the panic's engage is queued BEHIND it on
    // the pipe. Lifting from the mirror snapshot would open a window
    // (exchange answered alive, engage not yet applied) where a fresh
    // confirmation presents against an open gate.
    const presented = fakeProvider(installConfirmationProvider);
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    void requestKillStatus(); // occupies the slot, unanswered
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    expect(frames).toEqual([{ type: "kill_status" }, { type: "kill_engage" }]);
    await vi.advanceTimersByTimeAsync(0);

    // The pending exchange's answer lands: alive (a host-side release won
    // the race). The request gate is OPEN upstream and the engage is still
    // queued - the latch must hold.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The engage applies (killed), then a later explicit release (alive):
    // only THAT alive - ordered after the refusal - lifts the latch.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ());
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("an engage SEND FAILURE lifts the latch: nothing is in flight", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => false); // the post itself fails
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    // Nothing reached the pipe: the mirror tells the user the truth and
    // bricking every future confirmation would help no one.
    const later = confirmWithUser(WINDOW_REQ());
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);
  });

  test("releasePanicDeny is epoch-scoped (unit)", async () => {
    const first = denyAllConfirmations();
    const second = denyAllConfirmations();
    releasePanicDeny(first); // stale: must not lift the newer latch
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    releasePanicDeny(second);
    const presented = fakeProvider(installConfirmationProvider);
    const later = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("a pre-panic killed frame mid-write cannot serve as the panic's refusal proof", async () => {
    // A killed frame ARRIVES (a cross-surface engage push, or a stale status
    // answer) and its serialized mirror write is still in flight when the
    // panic lands. It must not count as the panic's phase-1 refusal: the
    // only refusal seen predates the engage, so a pre-panic exchange's alive
    // answer arriving next (a host-side release racing the brake) would
    // otherwise lift the latch with the engage still queued behind it.
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => true);
    void requestKillStatus(); // pre-panic exchange occupies the slot
    const preKilled = handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    route({ type: "confirm_deny_kill" }, confirmSender, () => {}); // same tick
    await preKilled;
    await vi.advanceTimersByTimeAsync(0);

    // The pre-panic exchange answers alive: the latch must hold.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The engage's own refusal, then an explicit release: now it lifts.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ());
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
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
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // The explicit presence-gated release settles everything: the latch
    // lifts - a send-failure repeat panic must not brick confirmations.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("an unknown answer to the engage is not refusal proof: a plain alive read cannot lift", async () => {
    // The host answering the engage ok:false means the kill write FAILED -
    // nothing applied. The unknown mirror refuses upstream (fail closed),
    // but it must not satisfy phase 1: otherwise a later plain alive read
    // (the host recovering, no release ever having happened) would lift the
    // latch without any presence-gated act.
    const presented = fakeProvider(installConfirmationProvider);
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    await handleKillFrame({ type: "kill_status_result", ok: false }); // engage failed host-side
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false }); // recovered: alive
    await vi.advanceTimersByTimeAsync(0);
    await expect(confirmWithUser(WINDOW_REQ())).resolves.toBe(false);
    expect(presented).toHaveLength(0);

    // Only a kill that provably TOOK, then the explicit release, lifts.
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: true });
    await handleKillFrame({ type: "kill_status_result", ok: true, killed: false });
    await vi.advanceTimersByTimeAsync(0);
    const later = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    resolveConfirm(presented[0]!.payload.id, false);
    await expect(later).resolves.toBe(false);
  });

  test("an unknown frame does not disarm the engage re-post", async () => {
    // ok:false is not proof the kill took, so the at-least-once re-post
    // must stay armed: a host that failed the kill write and then died
    // would otherwise swallow the brake.
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await vi.advanceTimersByTimeAsync(0);
    await handleKillFrame({ type: "kill_status_result", ok: false });
    detachPort();
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    expect(frames).toEqual([{ type: "kill_engage" }]);
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
    const verdict = confirmWithUser(WINDOW_REQ());
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

// The audit correlation id (ADR-0030): the extension mints one per-attempt
// `cid` and stamps it on EVERY audit event that attempt emits - its
// confirm_shown, its verdict, and a denial issued before any surface showed -
// so the desktop audit panel joins a verdict to exactly its own shown row. The
// security-relevant property, and the fix for the panic-latch bug: a denial of
// a confirmation that never reached a surface carries an id that matches no
// shown row, so it can never close an unrelated open confirmation.
describe("audit correlation id (cid)", () => {
  test("a confirmation's shown and its verdict share the same cid", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const verdict = confirmWithUser(WINDOW_REQ());
    await vi.advanceTimersByTimeAsync(0);
    const id = presented[0]!.payload.id;
    expect(resolveConfirm(id, true).ok).toBe(true);
    await expect(verdict).resolves.toBe(true);
    await vi.advanceTimersByTimeAsync(0);

    const ring = await readRing();
    const shown = ring.find((e) => e.kind === "confirm_shown");
    const allowed = ring.find((e) => e.kind === "confirm_allowed");
    expect(shown?.cid).toBe(id);
    expect(allowed?.cid).toBe(id);
    // A non-empty, collision-resistant id (crypto.randomUUID), not a guessable
    // counter, so a verdict cannot be steered to close another's row.
    expect(id).toMatch(/[0-9a-f]{8}-[0-9a-f]{4}/i);
  });

  test("the active denial reuses its shown cid; a never-shown denial gets a fresh cid that matches no row", async () => {
    const presented = fakeProvider(installConfirmationProvider);
    const first = confirmWithUser(WINDOW_REQ()); // shown, active
    const queued = confirmWithUser(WINDOW_REQ()); // waits behind the first, never shown
    await vi.advanceTimersByTimeAsync(0);
    expect(presented).toHaveLength(1);
    const shownId = presented[0]!.payload.id;

    // The panic latch: deny-and-kill settles the active one and drains the
    // queue without ever presenting a second surface.
    attachPort(() => true);
    route({ type: "confirm_deny_kill" }, confirmSender, () => {});
    await expect(first).resolves.toBe(false);
    await expect(queued).resolves.toBe(false);
    expect(presented).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(0);

    const ring = await readRing();
    const showns = ring.filter((e) => e.kind === "confirm_shown");
    const denials = ring.filter((e) => e.kind === "confirm_denied");
    // Exactly one confirmation was ever shown; its cid is the payload id.
    expect(showns.map((e) => e.cid)).toEqual([shownId]);
    // Two denials, both carrying a cid: the active confirmation's verdict reuses
    // its own shown cid (resolving its own row), while the queued one - denied
    // before any surface - carries a DISTINCT cid that matches no shown row, so
    // the audit panel resolves nothing from it. Neither denial is cid-less, so
    // neither can fall into the pre-upgrade subject fallback.
    const cids = denials.map((d) => d.cid);
    expect(cids).toHaveLength(2);
    expect(cids.every((c) => c !== undefined)).toBe(true);
    expect(cids.filter((c) => c === shownId)).toEqual([shownId]);
    const strayCid = cids.find((c) => c !== shownId);
    expect(strayCid).toBeDefined();
    expect(strayCid).not.toBe(shownId);
  });
});
