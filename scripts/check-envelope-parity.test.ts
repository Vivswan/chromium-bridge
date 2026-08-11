// The classifier-coverage rule of the envelope asymmetry gate
// (check-envelope-parity.ts): the classified inbound tag sets must EQUAL the
// gated inbound plans, modulo the pinned CLASSIFIED_OUTBOUND_TAGS ceremony
// exceptions. Exercised against the gate's REAL tables (importing the script
// is side-effect-free: the gate only runs under import.meta.main), so the
// regression the rule exists to prevent - a writer-only tag added to a
// classification array, routing inbound frames nothing validates - stays
// caught even if the surrounding script changes.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import {
  CLASSIFIED_TAGS,
  classifierCoverageProblems,
  FRAME_PLANS,
  FRAME_REFINEMENTS,
  GROUPS,
  type Group,
  refinementProblems,
} from "./check-envelope-parity";

// The Rust enum tags as the plan tables expect them; holding the real enum
// to the plans is the running gate's job (it needs the cargo-emitted
// schemas), not this test's.
function rustTags(group: Group): ReadonlySet<string> {
  return new Set(Object.keys(FRAME_PLANS[group]));
}

describe("classifierCoverageProblems", () => {
  test("today's real tables are clean for every group", () => {
    for (const group of GROUPS) {
      expect(classifierCoverageProblems(group, CLASSIFIED_TAGS[group], rustTags(group))).toEqual(
        [],
      );
    }
  });

  test("a writer-only tag added to a classification array is refused", () => {
    // THE regression this rule exists for: legacy_settings is a real policy
    // frame with a "rust-parsed" plan (extension->host, no inbound
    // validator); classifying it inbound must fail the gate, not silently
    // route host frames nothing validates.
    const classified = new Set([...CLASSIFIED_TAGS.policy, "legacy_settings"]);
    const problems = classifierCoverageProblems("policy", classified, rustTags("policy"));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("legacy_settings");
    expect(problems[0]).toContain("no plan gives it an inbound validator");
  });

  test("a classified tag that is not a Rust frame at all is refused", () => {
    const classified = new Set([...CLASSIFIED_TAGS.policy, "policy_nonexistent"]);
    const problems = classifierCoverageProblems("policy", classified, rustTags("policy"));
    expect(problems.join("\n")).toContain(
      "policy_nonexistent is not a frame of the Rust policy enum",
    );
  });

  test("a gated inbound frame dropped from its classification array is refused", () => {
    const classified = new Set([...CLASSIFIED_TAGS.policy].filter((t) => t !== "lang_current"));
    const problems = classifierCoverageProblems("policy", classified, rustTags("policy"));
    expect(problems).toEqual([
      "policy: inbound frame lang_current is gated but no runtime classifier routes it",
    ]);
  });

  test("an outbound exception pin that stops being classified is refused", () => {
    // The CLASSIFIED_OUTBOUND_TAGS pins bind both ways: the exception cannot
    // outlive the classification it excuses.
    const classified = new Set(
      [...CLASSIFIED_TAGS.enclave].filter((t) => t !== "enclave_challenge"),
    );
    const problems = classifierCoverageProblems("enclave", classified, rustTags("enclave"));
    expect(problems).toEqual([
      "classifier: pinned outbound tag enclave_challenge is no longer classified by the enclave arrays",
    ]);
  });
});

// The refinement-pin rule (FRAME_REFINEMENTS): a superRefine is invisible to
// z.toJSONSchema, so the structural diff cannot police it - these tests prove
// the behavioral pins refuse every way it could drift.
describe("refinementProblems", () => {
  test("today's real { zod } plans are clean against their pins", () => {
    for (const group of GROUPS) {
      for (const [tag, plan] of Object.entries(FRAME_PLANS[group])) {
        if (typeof plan !== "object") continue;
        const pins = FRAME_REFINEMENTS[tag as keyof typeof FRAME_REFINEMENTS] ?? [];
        expect(refinementProblems(tag, plan.zod, pins)).toEqual([]);
      }
    }
  });

  test("an unpinned refinement riding a frame validator is refused", () => {
    // THE regression this rule exists for: a superRefine added to a wrapped
    // validator without a FRAME_REFINEMENTS pin would be invisible to the
    // structural diff and could silently narrow (or fail to narrow) a
    // security frame.
    const sneaky = z.looseObject({ ok: z.boolean() }).superRefine(() => {});
    const problems = refinementProblems("kill_status_result", sneaky, []);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("1 custom refinement(s)");
    expect(problems[0]).toContain("pins 0");
  });

  test("a refinement NESTED below the frame level is counted too", () => {
    // The count walk is recursive: a .refine buried on a property (or deeper)
    // is exactly as invisible to z.toJSONSchema as a top-level superRefine,
    // so it must demand a pin the same way.
    const buried = z.looseObject({
      ok: z.boolean(),
      clients: z.array(z.looseObject({ name: z.string().refine((n) => n !== "x") })),
    });
    const problems = refinementProblems("client_list_result", buried, []);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("1 custom refinement(s)");
    // Built-in checks (min length and friends) surface in the structural
    // diff and are not counted as refinements.
    const bounded = z.looseObject({ ok: z.boolean(), name: z.string().min(1).max(8) });
    expect(refinementProblems("client_list_result", bounded, [])).toEqual([]);
  });

  test("a pinned refinement that vanished is refused (pins bind both ways)", () => {
    const unrefined = z.looseObject({ type: z.literal("policy_current"), ok: z.boolean() });
    const pins = FRAME_REFINEMENTS.policy_current ?? [];
    expect(pins.length).toBeGreaterThan(0);
    const problems = refinementProblems("policy_current", unrefined, pins);
    expect(problems.join("\n")).toContain("pins 1");
    // Without the refinement, the mixture probes parse: each is reported.
    expect(problems.join("\n")).toContain("no longer refuses");
  });

  test("a pinned refinement that stopped firing is refused even at the right count", () => {
    const inert = z
      .looseObject({ type: z.literal("policy_current"), ok: z.boolean() })
      .superRefine(() => {});
    const pins = FRAME_REFINEMENTS.policy_current ?? [];
    const problems = refinementProblems("policy_current", inert, pins);
    // The count matches, so every problem is a probe the no-op let through.
    expect(problems.length).toBeGreaterThan(0);
    for (const problem of problems) {
      expect(problem).toContain("no longer refuses");
    }
  });
});
