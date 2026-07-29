// The forwarding half of the extension audit ring (ADR-0030): whether an
// event reaches the host's durable trail is a property of its KIND alone.
// The per-call `forward` flag is gone - a call site must not be able to
// suppress forensic evidence for a forwarded kind, and the local-only kinds
// (which the host audits authoritatively when it handles them) must never
// leak a duplicate frame.

import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { attachPort, auditEvent, resetAuditForTests } from "@/lib/background/audit-log";

beforeEach(() => {
  fakeBrowser.reset();
  resetAuditForTests();
});

describe("audit forwarding derives from the kind alone", () => {
  test("a confirm event always goes to the host frame", () => {
    const frames: Array<Record<string, unknown>> = [];
    attachPort((frame) => {
      frames.push(frame as Record<string, unknown>);
      return true;
    });
    auditEvent("confirm_shown", { tool: "page_eval", name: "https://a.example", cid: "c1" });
    expect(frames).toEqual([
      {
        type: "audit_event",
        kind: "confirm_shown",
        tool: "page_eval",
        name: "https://a.example",
        cid: "c1",
      },
    ]);
  });

  test("local-only kinds are never forwarded", () => {
    const frames: unknown[] = [];
    attachPort((frame) => {
      frames.push(frame);
      return true;
    });
    auditEvent("kill_engaged", { outcome: "requested" });
    auditEvent("kill_status_changed", { outcome: "alive" });
    auditEvent("client_revoked", {});
    expect(frames).toEqual([]);
  });

  test("the per-call forward escape hatch does not exist", () => {
    // @ts-expect-error - auditEvent takes no options bag; reintroducing one
    // would let a call site typecheck while suppressing forwarded evidence
    auditEvent("confirm_shown", {}, { forward: false });
  });
});
