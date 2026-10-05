import { expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { OWNER_FILE, ownedTempDir, removeOwnedDir, sweepStaleDirs } from "./owned-dirs";
import { seedsDirOutsideRepo } from "./run";

const REPO = resolve(import.meta.dir, "..", "..");
const RUN = resolve(import.meta.dir, "run.ts");
const OWNED_DIRS = resolve(import.meta.dir, "owned-dirs.ts");

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

// The fixture roots are owned dirs under the driver's own prefixes, so a cancelled test run leaves
// nothing a later driver run cannot sweep.
test("the sweep removes only a dead owner's dirs of its prefixes (the protocol suites' leaked runtime dirs, same class)", () => {
  const root = ownedTempDir("bb-harness-sweep-");
  try {
    const gone = spawnSync(process.execPath, ["-e", ""]).pid;
    const make = (name: string, owner?: number | string): string => {
      const dir = join(root, name);
      mkdirSync(join(dir, "chromium-bridge"), { recursive: true });
      if (owner !== undefined) writeFileSync(join(dir, OWNER_FILE), `${owner}\n`);
      return dir;
    };
    const dead = make("bbh-dead", gone);
    make("bbh-live", process.pid);
    make("bbh-trailing-junk", `${gone}junk`);
    make("bbh-negative", -1);
    make("bb-harness-unrecorded");
    make("other-dead", gone);
    symlinkSync(root, join(root, "bbh-link"));
    const removed = sweepStaleDirs(["bb-harness-", "bbh-"], root);
    expect({ removed, survivors: readdirSync(root).sort() }).toEqual({
      removed: [dead],
      survivors: [
        "bb-harness-unrecorded",
        "bbh-link",
        "bbh-live",
        "bbh-negative",
        "bbh-trailing-junk",
        OWNER_FILE,
        "other-dead",
      ],
    });
  } finally {
    removeOwnedDir(root);
  }
});

test("SIGTERM removes the owned dirs before the process exits by the signal (a finally never runs on it)", async () => {
  if (process.platform === "win32") return;
  const root = ownedTempDir("bb-harness-sigterm-");
  const script = [
    `import { ownedTempDir, removeOwnedDirsOnSignals } from ${JSON.stringify(OWNED_DIRS)};`,
    "removeOwnedDirsOnSignals();",
    'console.log(ownedTempDir("bbh-"));',
    "setTimeout(() => {}, 60_000);",
  ].join("\n");
  const child = spawn(process.execPath, ["-e", script], {
    env: { ...process.env, TMPDIR: root },
    stdio: ["ignore", "pipe", "inherit"],
  });
  try {
    const dir = await new Promise<string>((done) => {
      child.stdout.once("data", (chunk) => done(String(chunk).trim()));
    });
    expect(existsSync(join(dir, OWNER_FILE))).toBe(true);
    child.kill("SIGTERM");
    const signal = await new Promise<NodeJS.Signals | null>((done) => {
      child.once("exit", (_code, sig) => done(sig));
    });
    expect({ signal, survivors: readdirSync(root) }).toEqual({
      signal: "SIGTERM",
      survivors: [OWNER_FILE],
    });
  } finally {
    child.kill("SIGKILL");
    removeOwnedDir(root);
  }
});
