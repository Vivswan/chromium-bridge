// The rules of the envelope asymmetry gate (check-envelope.ts), exercised against inputs a live run cannot
// produce: a table entry whose declared direction its probes contradict, a writer-only tag classified inbound,
// a refinement that vanished or stopped firing, a dead refinement counter. Importing the script runs no gate
// (main() only runs under import.meta.main); the one import-time check is the refinement counter's liveness
// probe, which throws rather than let a dead counter pass.

import { describe, expect, test } from "bun:test";
import { z } from "zod";
import { ASYMMETRIES, type Asymmetry } from "../../src/packages/shared/src/envelope-asymmetries";
import { PolicyOverlaySchema } from "../../src/packages/shared/src/policy.gen";
import {
  asymmetryProblems,
  CLASSIFIED_TAGS,
  classifierCoverageProblems,
  optionPaths,
  placeAt,
  type ReaderPair,
  readerPairs,
  readerRuleProblems,
  refinementCounterProblems,
  refinementProblems,
} from "../check-envelope";
import { GROUPS } from "../gen-envelope";

const pairs = readerPairs();

// The cross-file consistency the source cannot express: the table in envelope-asymmetries.ts against the
// validators envelope.gen.ts was generated from (and enclave.ts's refinement over policy_current).
describe("today's real table proves clean against the generated validators", () => {
  test("every entry and both reader rules", () => {
    const problems: string[] = [];
    for (const [kind, entries] of Object.entries(ASYMMETRIES)) {
      const pair = pairs[kind] as ReaderPair;
      for (const [path, entry] of Object.entries(entries)) {
        problems.push(...asymmetryProblems(`${kind} ${path}`, entry, pair, path));
      }
    }
    for (const [kind, pair] of Object.entries(pairs))
      problems.push(...readerRuleProblems(kind, pair));
    expect(problems).toEqual([]);
  });
});

describe("asymmetryProblems", () => {
  const request = pairs.request as ReaderPair;
  const idEntry = ASYMMETRIES.request?.["$.properties.id"] as Asymmetry;
  const opEntry = ASYMMETRIES.request?.["$.properties.op"] as Asymmetry;

  // THE regression this rule exists for: a direction that misstates what the validators do. Each case is one
  // table entry with one field changed and the problem the gate must name for it.
  const cases: readonly [string, Asymmetry, string, string][] = [
    [
      "a widen declared narrow (the base refuses an accepts probe)",
      { ...idEntry, direction: "narrow", probes: { accepts: ["req-9"], refuses: [] } },
      "$.properties.id",
      "a widening",
    ],
    [
      "a widen whose accepts probes the base also admits, without parser evidence",
      { ...idEntry, probes: { accepts: [7] } },
      "$.properties.id",
      "base admits every accepts probe",
    ],
    [
      "a widen with no accepts probe",
      { ...idEntry, probes: {} },
      "$.properties.id",
      "no accepts probe",
    ],
    [
      "a narrow with no refuses probe",
      { ...opEntry, probes: {} },
      "$.properties.op",
      "no refuses probe",
    ],
    [
      "a narrow whose refuses probe the base refuses too (proves nothing about this layer)",
      { ...opEntry, probes: { refuses: [7] } },
      "$.properties.op",
      "proves nothing about this layer",
    ],
    [
      "a refuses probe the enforced validator admits",
      { ...opEntry, probes: { refuses: ["tab_list"] } },
      "$.properties.op",
      "declared refused",
    ],
    [
      "an accepts probe the enforced validator refuses",
      { ...opEntry, probes: { refuses: [""], accepts: [""] } },
      "$.properties.op",
      "declared accepted",
    ],
  ];
  test.each(cases)("%s is refused", (_, entry, path, problem) => {
    expect(asymmetryProblems("request x", entry, request, path).join("\n")).toContain(problem);
  });

  test("a parser-level widen passes without a base-refused probe", () => {
    const anchor = pairs.client_list_result as ReaderPair;
    const path = "$.properties.clients.items.properties.anchor";
    const entry = ASYMMETRIES.client_list_result?.[path] as Asymmetry;
    expect(entry.evidence).toBe("parser");
    expect(asymmetryProblems("anchor", entry, anchor, path)).toEqual([]);
    expect(
      asymmetryProblems("anchor", { ...entry, evidence: undefined }, anchor, path).join(),
    ).toContain("base admits every accepts probe");
  });

  test("placeAt resolves property and items segments, is undefined off the frame, and refuses other segments", () => {
    const frame = { clients: [{ anchor: { kind: "hash", value: "v" } }], ok: true };
    expect(placeAt(frame, "$.properties.ok", false)).toEqual({ ...frame, ok: false });
    expect(
      placeAt(frame, "$.properties.clients.items.properties.anchor.properties.value", ""),
    ).toEqual({
      clients: [{ anchor: { kind: "hash", value: "" } }],
      ok: true,
    });
    expect(placeAt(frame, "$.items", 1)).toBeUndefined();
    expect(placeAt(frame, "$.properties.missing.properties.x", 1)).toBeUndefined();
    expect(() => placeAt(frame, "$.additionalProperties", 1)).toThrow("unsupported path segment");
  });

  test("a generated-schema replacement that admits an unknown field the base refuses is named", () => {
    // The successor of the old strict-overlay pin: the loose-frames rule never reaches a replaced node, so a
    // loose replacement would widen silently.
    const policy = pairs.policy_current as ReaderPair;
    const path = "$.properties.overlay";
    const entry = ASYMMETRIES.policy_current?.[path] as Asymmetry;
    const loose: ReaderPair = {
      ...policy,
      enforced: z.looseObject({
        type: z.literal("policy_current"),
        ok: z.boolean(),
        baseline: z.string().min(1).optional(),
        sig: z.string().min(1).optional(),
        overlay: z
          .looseObject({
            pageEvalEnabled: z.boolean().optional(),
            confirmGraceMs: z.int().optional(),
            disabledTools: z.array(z.string().min(1)).optional(),
            cdpMode: z.boolean().optional(),
          })
          .optional(),
      }),
    };
    expect(asymmetryProblems("overlay", entry, loose, path).join("\n")).toContain(
      "admits an unknown field the base refuses",
    );
    expect(asymmetryProblems("overlay", entry, policy, path)).toEqual([]);
  });
});

describe("readerRuleProblems", () => {
  const base = z
    .object({
      type: z.literal("t"),
      error: z.union([z.string(), z.null()]).optional(),
      inner: z
        .object({ note: z.union([z.string(), z.null()]).optional() })
        .strict()
        .optional(),
    })
    .strict();
  const frame = { type: "t", error: "e", inner: { note: "n" } };
  const enforcedShape = {
    type: z.literal("t"),
    error: z.string().optional(),
    inner: z.object({ note: z.string().optional() }).catchall(z.unknown()).optional(),
  };
  const clean: ReaderPair = {
    base,
    enforced: z.object(enforcedShape).catchall(z.unknown()),
    frames: [frame],
    loose: true,
  };

  test("the clean reader proves; the Option inventory comes from the base, nested paths included", () => {
    expect(readerRuleProblems("t", clean)).toEqual([]);
    expect(optionPaths(z.toJSONSchema(base))).toEqual([
      "$.properties.error",
      "$.properties.inner.properties.note",
    ]);
  });

  // THE regression this rule exists for: an enforced reader that keeps (or regrows) a null arm the host never
  // sends, at the top level or nested, or that no frame arm reaches.
  const cases: readonly [string, ReaderPair, string][] = [
    [
      "a top-level null arm kept",
      {
        ...clean,
        enforced: z
          .object({ ...enforcedShape, error: z.string().nullable().optional() })
          .catchall(z.unknown()),
      },
      "admits null at $.properties.error",
    ],
    [
      "a nested null arm kept",
      {
        ...clean,
        enforced: z
          .object({
            ...enforcedShape,
            inner: z
              .object({ note: z.string().nullable().optional() })
              .catchall(z.unknown())
              .optional(),
          })
          .catchall(z.unknown()),
      },
      "admits null at $.properties.inner.properties.note",
    ],
    [
      "an Option path no frame arm reaches",
      { ...clean, frames: [{ type: "t", error: "e" }] },
      "no representative frame carries $.properties.inner.properties.note",
    ],
    [
      "a control frame read strict",
      { ...clean, enforced: z.object(enforcedShape).strict() },
      "refuses an unknown field",
    ],
    [
      "a control frame read lax (the tag no longer gates)",
      { ...clean, enforced: z.looseObject({ ...enforcedShape, type: z.string() }) },
      "retagged frame is admitted",
    ],
    ["an envelope read loose", { ...clean, loose: false }, "admits an unknown field"],
  ];
  test.each(cases)("%s is named", (_, pair, problem) => {
    expect(readerRuleProblems("t", pair).join("\n")).toContain(problem);
  });
});

describe("classifierCoverageProblems", () => {
  test("today's real tables are clean for every group", () => {
    for (const group of GROUPS) {
      expect(classifierCoverageProblems(group, CLASSIFIED_TAGS[group])).toEqual([]);
    }
  });

  test("a writer-only tag added to a classification array is refused", () => {
    // THE regression this rule exists for: policy_get is a real policy frame with a writer plan
    // (extension->host, no reader); classifying it inbound must fail the gate, not silently route host frames
    // nothing validates.
    const problems = classifierCoverageProblems(
      "policy",
      new Set([...CLASSIFIED_TAGS.policy, "policy_get"]),
    );
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("policy_get");
    expect(problems[0]).toContain("no reader or bare tag covers it");
  });

  test("a classified tag that is not a planned frame at all is refused", () => {
    const problems = classifierCoverageProblems(
      "policy",
      new Set([...CLASSIFIED_TAGS.policy, "policy_nonexistent"]),
    );
    expect(problems.join("\n")).toContain(
      "policy_nonexistent is not a planned frame of the Rust policy enum",
    );
  });

  test("a gated inbound frame dropped from its classification array is refused", () => {
    const classified = new Set([...CLASSIFIED_TAGS.policy].filter((t) => t !== "lang_current"));
    expect(classifierCoverageProblems("policy", classified)).toEqual([
      "policy: inbound frame lang_current is gated but no runtime classifier routes it",
    ]);
  });

  test("an outbound exception pin that stops being classified is refused", () => {
    // The CLASSIFIED_OUTBOUND_TAGS pins bind both ways: the exception cannot outlive the classification it
    // excuses.
    const classified = new Set(
      [...CLASSIFIED_TAGS.enclave].filter((t) => t !== "enclave_challenge"),
    );
    expect(classifierCoverageProblems("enclave", classified)).toEqual([
      "classifier: pinned outbound tag enclave_challenge is no longer classified by the enclave arrays",
    ]);
  });
});

// The refinement-pin rule (FRAME_REFINEMENTS): a superRefine is invisible to the generator and to the probes,
// so these tests prove the behavioral pins refuse every way it could drift.
describe("refinementProblems", () => {
  test("an unpinned refinement riding an enforced reader is refused", () => {
    // THE regression this rule exists for: a superRefine added to a reader without a FRAME_REFINEMENTS pin
    // would be invisible to the generator and the probes and could silently narrow (or fail to narrow) a
    // security frame.
    const sneaky = z.looseObject({ ok: z.boolean() }).superRefine(() => {});
    const problems = refinementProblems("kill_status_result", sneaky, []);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("1 custom refinement(s)");
    expect(problems[0]).toContain("pins 0");
  });

  const counters: readonly [string, (schema: z.ZodType) => number, readonly string[]][] = [
    ["a dead counter (reads 0 everywhere)", () => 0, ["one .superRefine", "one .refine nested"]],
    ["an over-counting counter (reads 1 everywhere)", () => 1, ["built-in checks only"]],
  ];
  test.each(counters)(
    "%s is refused by the liveness probe, naming each failed probe",
    (_, count, names) => {
      // refinementCounterProblems owns the failure mode it closes.
      const problems = refinementCounterProblems(count);
      expect(problems).toHaveLength(names.length);
      for (const [i, name] of names.entries()) {
        expect(problems[i]).toContain(`refinement counter: ${name}`);
      }
    },
  );

  // The real table pins nothing, so the two-way binding is proven on a pin and schema written here.
  const splitPin = {
    name: "ok-split",
    refuses: [{ type: "verdict", ok: true, error: "boom" }],
    accepts: [{ type: "verdict", ok: true }],
  };

  test("a pinned refinement that vanished is refused (pins bind both ways)", () => {
    const unrefined = z.looseObject({ type: z.literal("verdict"), ok: z.boolean() });
    const problems = refinementProblems("verdict", unrefined, [splitPin]);
    expect(problems.join("\n")).toContain("pins 1");
    // Without the refinement, the mixture probe parses: it is reported.
    expect(problems.join("\n")).toContain("no longer refuses");
  });

  test("a pinned refinement that stopped firing is refused even at the right count", () => {
    const inert = z
      .looseObject({ type: z.literal("verdict"), ok: z.boolean() })
      .superRefine(() => {});
    const problems = refinementProblems("verdict", inert, [splitPin]);
    // The count matches, so every problem is a probe the no-op let through.
    expect(problems.length).toBeGreaterThan(0);
    for (const problem of problems) {
      expect(problem).toContain("no longer refuses");
    }
  });
});

describe("probe arms must carry the field they prove", () => {
  test("an entry whose path no arm carries is named, and an arm that cannot carry it is never used", () => {
    // THE masking this rule exists for: on the ok:true arm the ok-split refuses an inserted `error`, so a
    // probe placed there would pass for an enforced error field that admits anything.
    const policy = pairs.policy_current as ReaderPair;
    const entry: Asymmetry = {
      direction: "narrow",
      reason: "r",
      changes: [{ change: "string", minLength: 1 }],
      probes: { refuses: [""] },
    };
    const lax: ReaderPair = {
      ...policy,
      enforced: z
        .looseObject({
          type: z.literal("policy_current"),
          ok: z.boolean(),
          baseline: z.string().min(1).optional(),
          error: z.union([z.string(), z.number()]).optional(),
        })
        .superRefine((frame, ctx) => {
          if (frame.ok && frame.error !== undefined)
            ctx.addIssue({ code: "custom", message: "split" });
        }),
    };
    expect(asymmetryProblems("error", entry, lax, "$.properties.error").join("\n")).toContain(
      "declared refused",
    );
    const onlyOkTrue: ReaderPair = { ...lax, frames: [lax.frames[0]] };
    expect(asymmetryProblems("error", entry, onlyOkTrue, "$.properties.error")).toEqual([
      "error: no representative frame carries the path",
    ]);
  });

  test("the Option inventory skips a required nullable property (a value the generator keeps) but walks its children", () => {
    // `inner` is itself required and nullable: skipped as an Option, its optional nullable child still found.
    const base = z
      .object({
        label: z.union([z.string(), z.null()]),
        note: z.union([z.string(), z.null()]).optional(),
        inner: z.union([
          z.object({ tag: z.union([z.string(), z.null()]).optional() }).strict(),
          z.null(),
        ]),
      })
      .strict();
    expect(optionPaths(z.toJSONSchema(base))).toEqual([
      "$.properties.note",
      "$.properties.inner.properties.tag",
    ]);
  });

  test("the Option inventory names an Option path only the missing arm carries, instead of proving it on an arm that cannot", () => {
    // The reader-side twin of the entry rule: with only the ok:true arm, `error` has no carrying arm and the
    // ok-split would refuse an inserted null for its own reason. The enforced validator is the real generated
    // shape with one regrown null arm on error.
    const policy = pairs.policy_current as ReaderPair;
    const enforced = z
      .looseObject({
        type: z.literal("policy_current"),
        ok: z.boolean(),
        baseline: z.string().min(1).optional(),
        sig: z.string().min(1).optional(),
        overlay: PolicyOverlaySchema.optional(),
        error: z.string().nullable().optional(),
      })
      .superRefine((frame, ctx) => {
        if (frame.ok && frame.error !== undefined)
          ctx.addIssue({ code: "custom", message: "split" });
      });
    const okTrueOnly: ReaderPair = { ...policy, enforced, frames: [policy.frames[0]] };
    expect(readerRuleProblems("policy_current", okTrueOnly)).toEqual([
      "policy_current: optional-only: no representative frame carries $.properties.error",
    ]);
    expect(readerRuleProblems("policy_current", { ...policy, enforced })).toEqual([
      "policy_current: optional-only: the enforced validator admits null at $.properties.error",
    ]);
  });
});
