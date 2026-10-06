// The panic brake: one state for the confirm window's deny-and-kill and for the at-least-once engage re-post.
// kill.ts feeds it (the posts, the committed frames); confirm/service.ts reads the latch and the panic epoch, kill.ts
// the re-post.
//
// Frames are the only evidence (at panic time the mirror can read a stale "killed" with a release about to write
// "alive"), and a frame counts only if it ARRIVED after the watermark it is judged against: kill.ts stamps arrivals
// before the serialized mirror write, so a pre-panic frame whose write commits late stays pre-panic.
// "unknown" (the kill WRITE failed host-side) advances nothing: as a refusal it would let a plain alive read lift
// the latch, as a confirmation it would let a dying host swallow the brake.
// Residual (docs/security/trust-boundaries.md): a cross-surface kill push already in flight at panic time counts as
// its refusal one frame early; only a presence-gated release racing the brake can produce one.

import type { KillMirror } from "@chromium-bridge/shared/enclave";
import { unreachable } from "@chromium-bridge/shared/util";
import { inLife } from "../shared/in-life";

/** Watermarks are arrival stamps: `engage` is the latest engage's post (re-posted on reconnect until a killed frame
 * arrives after it), `anchor` is where the panic latch counts evidence from (the engage outstanding when the panic
 * landed, else its own post). */
export type Brake =
  | { readonly kind: "clear" }
  /** An engage on the pipe with no panic (the options page). */
  | { readonly kind: "engaged"; readonly engage: number }
  /** Confirmations latched; waiting for a killed frame after `anchor`. */
  | { readonly kind: "braking"; readonly anchor: number; readonly engage: number }
  /** The kill provably applied; latched until an alive frame after `anchor`, which only a presence-gated release
   * produces. A later engage may still await its own killed frame. */
  | { readonly kind: "awaiting-release"; readonly anchor: number; readonly engage: number | null };

export type BrakeEvent =
  /** An engage reached the pipe outside a panic: the options page, or the reconnect re-post. */
  | { type: "engage-posted" }
  /** The confirm window's deny-and-kill; `posted` says whether its own engage reached the pipe. */
  | { type: "panic"; posted: boolean }
  /** One kill_status_result COMMITTED to the mirror (the gate enforces on the stored state, so a frame merely seen
   * proves nothing), stamped `seq` when it arrived. */
  | { type: "frame"; state: KillMirror["state"]; seq: number };

const CLEAR: Brake = { kind: "clear" };

/** `now` is the arrival watermark an engage posted in this synchronous turn carries. */
function transition(brake: Brake, event: BrakeEvent, now: number): Brake {
  switch (event.type) {
    case "engage-posted":
      return brake.kind === "clear" ? { kind: "engaged", engage: now } : { ...brake, engage: now };
    case "panic": {
      const outstanding = brake.kind === "clear" ? null : brake.engage;
      if (event.posted) return { kind: "braking", anchor: outstanding ?? now, engage: now };
      // Nothing reached the pipe and nothing was outstanding: the mirror tells the user the truth, and latching
      // every future confirmation would help no one. An outstanding engage IS the brake this panic wants.
      if (outstanding === null) return brake;
      return { kind: "braking", anchor: outstanding, engage: outstanding };
    }
    case "frame":
      switch (brake.kind) {
        case "clear":
          return brake;
        case "engaged":
          return event.state === "killed" && event.seq > brake.engage ? CLEAR : brake;
        case "braking":
          if (event.state !== "killed" || event.seq <= brake.anchor) return brake;
          return {
            kind: "awaiting-release",
            anchor: brake.anchor,
            engage: event.seq > brake.engage ? null : brake.engage,
          };
        case "awaiting-release":
          if (event.state === "killed" && brake.engage !== null && event.seq > brake.engage) {
            return { ...brake, engage: null };
          }
          if (event.state === "alive" && event.seq > brake.anchor) {
            return brake.engage === null ? CLEAR : { kind: "engaged", engage: brake.engage };
          }
          return brake;
        default:
          return unreachable(brake);
      }
    default:
      return unreachable(event);
  }
}

// Arrivals are never reset: a handler still running from a previous test, stamped before the reset, must not outrank
// a new watermark.
const arrivals = inLife(() => 0);
// The panic count, bumped on every panic event whether or not it moved the state (a panic whose engage never reached
// the pipe still denies the decisions it crossed). The level (confirmationsLatched) cannot see a panic that lands AND
// lifts between a decision's start and its presentation; the count can. Never reset, like arrivals.
const panics = inLife(() => 0);
const brake = inLife<Brake>(() => CLEAR);

/** Stamp one inbound kill_status_result on arrival, before its serialized mirror write. */
export function stampArrival(): number {
  arrivals.value += 1;
  return arrivals.value;
}

export function advance(event: BrakeEvent): void {
  if (event.type === "panic") panics.value += 1;
  brake.value = transition(brake.value, event, arrivals.value);
}

/** The epoch a decision captures at its start; ConfirmRequestBase.panicEpoch (confirm/service.ts) owns when and why. */
export function currentPanicEpoch(): number {
  return panics.value;
}

/** An engage reached the pipe and no killed frame has arrived since; the next attach re-posts it. */
export function engageOutstanding(): boolean {
  return brake.value.kind !== "clear" && brake.value.engage !== null;
}

/** Every confirmation denies without presenting while a panic's brake is in flight or awaiting its release. */
export function confirmationsLatched(): boolean {
  return brake.value.kind === "braking" || brake.value.kind === "awaiting-release";
}

/** Tests only. */
export function resetBrakeForTests(): void {
  brake.reset();
}
