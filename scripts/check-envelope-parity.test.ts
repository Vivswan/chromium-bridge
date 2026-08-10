// The classifier-coverage rule of the envelope asymmetry gate
// (check-envelope-parity.ts): the classified inbound tag sets must EQUAL the
// gated inbound plans, modulo the pinned CLASSIFIED_OUTBOUND_TAGS ceremony
// exceptions. Exercised against the gate's REAL tables (importing the script
// is side-effect-free: the gate only runs under import.meta.main), so the
// regression the rule exists to prevent - a writer-only tag added to a
// classification array, routing inbound frames nothing validates - stays
// caught even if the surrounding script changes.

import { describe, expect, test } from "bun:test";
import {
  CLASSIFIED_TAGS,
  classifierCoverageProblems,
  FRAME_PLANS,
  GROUPS,
  type Group,
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
