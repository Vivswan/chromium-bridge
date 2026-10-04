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
  commandArgsProblems,
  commandCoverageProblems,
  FRAME_PLANS,
  FRAME_REFINEMENTS,
  GROUPS,
  type Group,
  normalizeCommandArgs,
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
    // THE regression this rule exists for: policy_get is a real policy
    // frame with a "rust-parsed" plan (extension->host, no inbound
    // validator); classifying it inbound must fail the gate, not silently
    // route host frames nothing validates.
    const classified = new Set([...CLASSIFIED_TAGS.policy, "policy_get"]);
    const problems = classifierCoverageProblems("policy", classified, rustTags("policy"));
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("policy_get");
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

// R6: the request's typed command, per op. The Rust fixtures are the exact shapes schemars emits for an
// args struct (the JsInt bounds, `default` on a serde-defaulted field, no `properties` on an empty struct);
// the Zod side is what gen-ops.ts emits for the same struct. The mutation cases prove that a validator
// drifting from its struct is CAUGHT, in both directions.
describe("commandArgsProblems (R6)", () => {
  const JS_SAFE = Number.MAX_SAFE_INTEGER;
  const jsInt = { type: "integer", minimum: -JS_SAFE, maximum: JS_SAFE };
  const rustWaitFor = {
    type: "object",
    additionalProperties: false,
    properties: {
      nav: { description: "Wait for a navigation event", type: "boolean" },
      selector: { description: "Wait for this selector", type: "string" },
      timeoutMs: { default: 30000, description: "Max wait in ms", ...jsInt },
    },
  };
  const zodWaitFor = z
    .object({
      nav: z.boolean().optional(),
      selector: z.string().optional(),
      timeoutMs: z.number().int().optional(),
    })
    .strict();

  test("today's real derivations of one struct are equivalent", () => {
    expect(commandArgsProblems("page_wait_for", rustWaitFor, zodWaitFor)).toEqual([]);
    // An empty struct: schemars omits `properties`, Zod emits `{}`.
    expect(
      commandArgsProblems(
        "tab_list",
        { type: "object", additionalProperties: false },
        z.object({}).strict(),
      ),
    ).toEqual([]);
  });

  test("a validator missing a field, or carrying one the struct lacks, is refused", () => {
    const missing = z
      .object({ nav: z.boolean().optional(), selector: z.string().optional() })
      .strict();
    expect(commandArgsProblems("page_wait_for", rustWaitFor, missing).join()).toContain(
      "timeoutMs",
    );
    const extra = zodWaitFor.extend({ text: z.string().optional() });
    expect(commandArgsProblems("page_wait_for", rustWaitFor, extra).join()).toContain("text");
  });

  test("a validator widening a field or dropping required-ness is refused", () => {
    const widened = z
      .object({
        nav: z.string().optional(),
        selector: z.string().optional(),
        timeoutMs: z.number().int().optional(),
      })
      .strict();
    expect(commandArgsProblems("page_wait_for", rustWaitFor, widened).join()).toContain("nav");
    const rustRequired = {
      type: "object",
      additionalProperties: false,
      properties: { tabId: jsInt },
      required: ["tabId"],
    };
    expect(
      commandArgsProblems(
        "tab_focus",
        rustRequired,
        z.object({ tabId: z.number().int().optional() }).strict(),
      ).join(),
    ).toContain("required");
    expect(
      commandArgsProblems(
        "tab_focus",
        rustRequired,
        z.object({ tabId: z.number().int() }).strict(),
      ),
    ).toEqual([]);
  });

  test("a raw i64 field is a parser disagreement, not an erased width claim", () => {
    // 2^53 parses as i64 on the host and is refused by z.int() in the extension; the Rust args spell
    // integers as JsInt so the bounds appear on both sides, and a struct that slips back to i64
    // (schemars: int64, unbounded) must fail here rather than be canonicalized away.
    const rustRawInt = {
      type: "object",
      additionalProperties: false,
      properties: { pixels: { format: "int64", type: "integer" } },
    };
    expect(
      commandArgsProblems(
        "page_scroll",
        rustRawInt,
        z.object({ pixels: z.number().int().optional() }).strict(),
      ).join(),
    ).toContain("pixels");
  });

  test("a side losing strictness is refused, not compared away", () => {
    expect(() => normalizeCommandArgs({ type: "object", properties: {} }, "rust")).toThrow(
      "not strict",
    );
    expect(() => normalizeCommandArgs(z.toJSONSchema(z.looseObject({})), "zod")).toThrow(
      "not strict",
    );
    // `default` is erased on the Rust side only: a Zod .default() would hand the extension a value the
    // frame never carried.
    expect(normalizeCommandArgs({ type: "boolean", default: true }, "rust")).toEqual({
      type: "boolean",
    });
    expect(normalizeCommandArgs({ type: "boolean", default: true }, "zod")).toEqual({
      type: "boolean",
      default: true,
    });
  });
});

describe("commandCoverageProblems (R6)", () => {
  test("the same op set both ways is clean; a tool on one side only is named", () => {
    expect(
      commandCoverageProblems(new Set(["tab_list", "page_eval"]), ["page_eval", "tab_list"]),
    ).toEqual([]);
    expect(commandCoverageProblems(new Set(["tab_list", "tab_rename"]), ["tab_list"])).toEqual([
      "command tab_rename: a Rust tool with no generated validator",
    ]);
    expect(commandCoverageProblems(new Set(["tab_list"]), ["tab_list", "tab_rename"])).toEqual([
      "command tab_rename: a generated validator with no Rust tool",
    ]);
  });
});
