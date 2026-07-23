import { describe, expect, test } from "bun:test";
import { ALLOWED_TYPES, isMergeSubject, sanitizeForLog, subjectError } from "./check-commit-names";

describe("subjectError", () => {
  test("accepts every CONTRIBUTING.md type", () => {
    for (const type of ALLOWED_TYPES) {
      expect(subjectError(`${type}: do the thing`)).toBeNull();
    }
  });

  test("the type list is CONTRIBUTING.md's, so chore is not in it", () => {
    expect(ALLOWED_TYPES).not.toContain("chore");
  });

  test.each([
    "feat(session): add tab pooling",
    "feat!: drop the legacy handshake",
    "fix(ipc/broker)!: reject unknown peers",
    "build(deps): bump serde",
    "ci: gate release and audits behind all-green",
  ])("accepts %j", (value) => {
    expect(subjectError(value)).toBeNull();
  });

  test("accepts release-please's release subject (the one chore carve-out)", () => {
    expect(subjectError("chore(main): release 3.0.0")).toBeNull();
    expect(subjectError("chore(main): release chromium-bridge 3.0.0")).toBeNull();
  });

  test("rejects plain chore (CONTRIBUTING.md bans the type)", () => {
    expect(subjectError("chore: cleanup")).not.toBeNull();
    expect(subjectError("chore(deps): bump serde")).not.toBeNull();
    expect(subjectError("chore(release): release 3.0.0")).not.toBeNull();
    // The carve-out needs something after "release" - release-please always
    // appends a version.
    expect(subjectError("chore(main): release")).not.toBeNull();
  });

  test.each([
    "add a feature",
    "feat:missing space after colon",
    "unknown: made-up type",
    "feat(bad scope): spaces in the scope",
    "feat : space before colon",
    "feat: ",
    "",
  ])("rejects %j", (value) => {
    expect(subjectError(value)).not.toBeNull();
  });

  test("rejects control characters (C0, DEL, C1)", () => {
    const cases = [
      "feat: x\ninjected line",
      "feat: x\rinjected",
      "feat: x\u001b[31mred", // ESC starts a terminal escape sequence
      "feat: x\u007fy", // DEL
      "feat: x\u0085y", // NEL, a C1 control
    ];
    for (const value of cases) {
      expect(subjectError(value)).toContain("control characters");
    }
  });

  test("rejects the JS line terminators outside Cc (U+2028, U+2029)", () => {
    expect(subjectError("feat: ok\u2028::error::injected")).toContain("control characters");
    expect(subjectError("feat: ok\u2029::error::injected")).toContain("control characters");
  });

  test("a control character loses to nothing: even a release subject is refused", () => {
    expect(subjectError("chore(main): release 3.0.0\n::error::owned")).toContain(
      "control characters",
    );
  });
});

describe("sanitizeForLog", () => {
  test("neutralizes everything the control class rejects", () => {
    expect(sanitizeForLog("a\nb\u001b[31mc\u2028d")).toBe("a\ufffdb\ufffd[31mc\ufffdd");
  });

  test("leaves ordinary text alone", () => {
    expect(sanitizeForLog("feat(scope)!: plain subject")).toBe("feat(scope)!: plain subject");
  });
});

describe("isMergeSubject", () => {
  // Range modes exclude merges by parent count (git rev-list --no-merges);
  // this text heuristic only guards the push-payload fallback, where parent
  // information is unavailable.
  test("matches git's merge-commit subjects", () => {
    expect(isMergeSubject("Merge pull request #9 from o/b")).toBe(true);
    expect(isMergeSubject("Merge branch 'main' into feat/x")).toBe(true);
    expect(isMergeSubject("Merge branches 'a' and 'b'")).toBe(true);
    expect(isMergeSubject("Merge remote-tracking branch 'origin/main'")).toBe(true);
    expect(isMergeSubject("Merge tag 'v1.0.0'")).toBe(true);
    expect(isMergeSubject("Merge commit 'abc123'")).toBe(true);
  });

  test("does not match ordinary subjects mentioning merges", () => {
    expect(isMergeSubject("feat: merge two allowlist sources")).toBe(false);
    expect(isMergeSubject("Merges everything")).toBe(false);
  });
});
