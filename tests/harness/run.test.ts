import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { seedsDirOutsideRepo } from "./run";

const REPO = resolve(import.meta.dir, "..", "..");
const RUN = resolve(import.meta.dir, "run.ts");

test("--mint-seeds refuses an output dir inside the repository (the captured-corpus incident)", () => {
  const outside = mkdtempSync(join(tmpdir(), "harness-seeds-"));
  try {
    // Symlinks defeat a lexical comparison: a link outside the repo that points inside must still
    // be refused, and one that points elsewhere outside must still be accepted.
    symlinkSync(join(REPO, "src"), join(outside, "into-repo"));
    mkdirSync(join(outside, "real"));
    symlinkSync(join(outside, "real"), join(outside, "elsewhere"));
    const cases: [reason: string, dir: string, expected: "accepted" | "refused"][] = [
      [
        "the former in-repo corpus dir",
        join(REPO, "src/packages/core/fuzz/seeds/mcp_jsonrpc"),
        "refused",
      ],
      ["the repository root itself", REPO, "refused"],
      ["a dot-dot-prefixed child of the root", join(REPO, "..seeds"), "refused"],
      [
        "a relative path that resolves inside",
        relative(process.cwd(), join(REPO, "build", "seeds")),
        "refused",
      ],
      [
        "a not-yet-existing dir under a symlink into the repo",
        join(outside, "into-repo", "seeds"),
        "refused",
      ],
      ["a temp dir", outside, "accepted"],
      [
        "a dir under a symlink to another outside dir",
        join(outside, "elsewhere", "seeds"),
        "accepted",
      ],
      ["the repository's parent", resolve(REPO, ".."), "accepted"],
    ];
    const verdicts = cases.map(([reason, dir]) => {
      try {
        return [
          reason,
          seedsDirOutsideRepo(dir, REPO) === resolve(dir) ? "accepted" : "wrong path",
        ];
      } catch {
        return [reason, "refused"];
      }
    });
    expect(verdicts).toEqual(cases.map(([reason, , expected]) => [reason, expected]));

    // The trailing bad flag keeps a regressed guard from launching the harnesses: parsing then
    // fails on that flag instead, and the refusal text is what tells the two apart.
    const inside = join(REPO, "build", "seeds");
    const refused = spawnSync(process.execPath, [RUN, "--mint-seeds", inside, "--not-a-flag"], {
      encoding: "utf8",
    });
    const missing = spawnSync(process.execPath, [RUN, "--mint-seeds"], { encoding: "utf8" });
    expect({
      refused: { status: refused.status, stderr: refused.stderr.split("\n")[0] },
      missing: { status: missing.status, stderr: missing.stderr.split("\n")[0] },
    }).toEqual({
      refused: {
        status: 2,
        stderr: `error: refusing to write captured frames inside the repository: ${inside}`,
      },
      missing: { status: 2, stderr: "error: --mint-seeds needs <dir>" },
    });
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});
