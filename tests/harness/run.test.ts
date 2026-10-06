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
const FAKE_LLM = resolve(import.meta.dir, "fake-llm.ts");

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

    // A regressed guard would go on to launch the harnesses: TMPDIR names a dir that does not exist,
    // so the stale-dir sweep right after parsing dies instead, and the refusal text is what tells the
    // two apart.
    const inside = join(REPO, "build", "seeds");
    const env = { ...process.env, TMPDIR: join(outside, "no-such-tmp") };
    const refused = spawnSync(process.execPath, [RUN, "--mint-seeds", inside], {
      encoding: "utf8",
      env,
    });
    const missing = spawnSync(process.execPath, [RUN, "--mint-seeds"], { encoding: "utf8", env });
    expect({
      refused: { status: refused.status, stderr: refused.stderr.split("\n")[0] },
      missing: { status: missing.status, stderr: missing.stderr },
    }).toEqual({
      refused: {
        status: 2,
        stderr: `error: refusing to write captured frames inside the repository: ${inside}`,
      },
      missing: { status: 2, stderr: expect.stringMatching(/usage:/) },
    });
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});

// The driver passes --portfile on the command line: a mistyped flag or one without its path must exit
// before a port is bound, or the driver would wait on a portfile that never appears. A regressed parse
// starts the server, which runs until its lifetime bound, so the spawn is bounded well under that.
test("fake-llm exits 2 with its usage on an unknown flag or a --portfile without its path", () => {
  const outcomes = [["--bogus"], ["--portfile"]].map((args) => {
    const result = spawnSync(process.execPath, [FAKE_LLM, ...args], {
      encoding: "utf8",
      timeout: 10_000,
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  });
  expect(outcomes).toEqual([
    { status: 2, stdout: "", stderr: expect.stringMatching(/usage:/) },
    { status: 2, stdout: "", stderr: expect.stringMatching(/usage:/) },
  ]);
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

// The sleeper is the child's own child: the child reaps it and reports its exit over stdout, so this
// test never probes or signals a pid it did not spawn. A write to fd 1 is synchronous, so the report
// lands before the child re-raises the signal and dies. The child's normal completion is the driver's
// shape: it awaits the sleeper, which the signal's SIGKILL also completes, then joins the teardown and
// would exit 7 on its own. The reap is asserted because under a non-reaping init (a CI container) an
// unreaped orphan is a zombie that still reads as alive.
test("SIGTERM stops and reaps the owned child, removes the owned dirs, then exits by the signal, even when the kill completes the run or a second signal lands (a finally never runs on a signal)", async () => {
  if (process.platform === "win32") return;
  const root = ownedTempDir("bb-harness-sigterm-");
  const script = [
    `import { joinSignalTeardown, ownedChild, ownedTempDir, teardownOnSignals } from ${JSON.stringify(OWNED_DIRS)};`,
    'import { spawn } from "node:child_process";',
    'import { once } from "node:events";',
    'import { writeSync } from "node:fs";',
    "teardownOnSignals();",
    'const sleeper = ownedChild(spawn(process.execPath, ["-e", "setTimeout(() => {}, 20_000)"], { stdio: "ignore" }));',
    'sleeper.once("exit", (code, sig) => writeSync(1, JSON.stringify({ sleeperExit: sig ?? code }) + "\\n"));',
    'writeSync(1, JSON.stringify({ dir: ownedTempDir("bbh-") }) + "\\n");',
    'await once(sleeper, "exit");',
    "await joinSignalTeardown();",
    "process.exit(7);",
  ].join("\n");
  const child = spawn(process.execPath, ["-e", script], {
    env: { ...process.env, TMPDIR: root },
    stdio: ["ignore", "pipe", "inherit"],
  });
  try {
    let output = "";
    const started = await new Promise<{ dir: string }>((done) => {
      child.stdout.on("data", (chunk) => {
        output += String(chunk);
        if (output.includes("\n")) done(JSON.parse(output.slice(0, output.indexOf("\n"))));
      });
    });
    expect(existsSync(join(started.dir, OWNER_FILE))).toBe(true);
    // A second signal of another kind lands while the first teardown reaps; it must not start an
    // empty teardown that exits at once. Which of the two ends the process depends on delivery order.
    child.kill("SIGTERM");
    child.kill("SIGINT");
    const exit = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
      (done) => {
        child.once("exit", (code, signal) => done({ code, signal }));
      },
    );
    const reports = output
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect({ exit, survivors: readdirSync(root), reports }).toEqual({
      exit: { code: null, signal: expect.stringMatching(/^SIG(TERM|INT)$/) },
      survivors: [OWNER_FILE],
      reports: [{ dir: started.dir }, { sleeperExit: "SIGKILL" }],
    });
  } finally {
    child.kill("SIGKILL");
    removeOwnedDir(root);
  }
}, 20_000);
