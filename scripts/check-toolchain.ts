#!/usr/bin/env bun
// Verify the duplicated toolchain pins agree. proto (.prototools) is the
// bootstrap toolchain manager, but four of its pins are necessarily
// duplicated elsewhere, and a silent disagreement would mean local runs and
// CI use different tools:
//
//   rust  - rust-toolchain.toml is the AUTHORITATIVE pin (rustup, IDEs, and
//           CI's setup-rust-toolchain read it natively, and it carries the
//           components + profile that proto cannot express). The .prototools
//           rust entry only pre-installs that toolchain and must match.
//   bun   - package.json's packageManager field (read by setup-bun in the
//           CI jobs that do not go through proto) must match.
//   proto/moon - .github/workflows/ci.yml passes explicit proto-version /
//           moon-version inputs to moonrepo/setup-toolchain (the action
//           cannot read the proto pin from .prototools itself); every
//           occurrence must match the .prototools pins.
//
// uv is pinned ONLY in .prototools (single authority - nothing to diff),
// and python is owned by uv via .python-version (proto's builtin-plugins
// allow-list deliberately excludes python; asserted here too).
//
// Run via `moon run check-toolchain` (part of the ci gate) and CI's
// version-consistency job.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

let failed = false;
function fail(message: string): void {
  console.error(`MISMATCH: ${message}`);
  failed = true;
}

const prototools = readFileSync(join(repoRoot, ".prototools"), "utf8");

// Pins live above the first [table]; a simple key = "value" scan suffices.
const pins = new Map<string, string>();
for (const line of prototools.split("\n")) {
  if (line.startsWith("[")) break;
  const match = line.match(/^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/);
  if (match) pins.set(match[1] as string, match[2] as string);
}

function pin(tool: string): string {
  const value = pins.get(tool);
  if (!value) {
    fail(`.prototools does not pin ${tool}`);
    return "<missing>";
  }
  return value;
}

// rust: .prototools must match rust-toolchain.toml's channel (the authority).
const rustToolchain = readFileSync(join(repoRoot, "rust-toolchain.toml"), "utf8");
const channel = rustToolchain.match(/^channel\s*=\s*"([^"]+)"/m)?.[1];
if (!channel) {
  fail("rust-toolchain.toml has no channel pin");
} else if (pin("rust") !== channel) {
  fail(`.prototools rust (${pin("rust")}) != rust-toolchain.toml channel (${channel})`);
}
console.log(`rust   ${channel ?? "<missing>"} (authority: rust-toolchain.toml)`);

// bun: .prototools must match package.json's packageManager.
const rootPkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8")) as {
  packageManager?: string;
};
const packageManager = rootPkg.packageManager ?? "";
const bunFromPkg = packageManager.match(/^bun@(.+)$/)?.[1];
if (!bunFromPkg) {
  fail(`package.json packageManager (${packageManager}) is not a bun pin`);
} else if (pin("bun") !== bunFromPkg) {
  fail(`.prototools bun (${pin("bun")}) != package.json packageManager (${bunFromPkg})`);
}
console.log(`bun    ${bunFromPkg ?? "<missing>"} (package.json packageManager)`);

// proto + moon: EVERY moonrepo/setup-toolchain step in ci.yml must be
// SHA-pinned and carry both explicit version inputs in its `with:` block,
// each matching the .prototools pin - checked per step (not "some match
// exists somewhere") so a single drifting or de-pinned job cannot hide
// behind the others. Parsed as real YAML (Bun.YAML), not regex-scraped, so
// look-alike text in env blocks, comments, or multiline scalars cannot
// stand in for an actual action input.
const ciYml = readFileSync(join(repoRoot, ".github/workflows/ci.yml"), "utf8");
interface WorkflowStep {
  uses?: string;
  with?: Record<string, unknown>;
}
const workflow = Bun.YAML.parse(ciYml) as {
  jobs?: Record<string, { steps?: WorkflowStep[] }>;
};
let invocations = 0;
for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
  for (const step of job.steps ?? []) {
    // Action owner/repo are case-insensitive on GitHub - match accordingly
    // so a re-cased `Moonrepo/Setup-Toolchain@...` cannot evade the check.
    if (
      typeof step.uses !== "string" ||
      !step.uses.toLowerCase().startsWith("moonrepo/setup-toolchain@")
    ) {
      continue;
    }
    invocations += 1;
    const where = `ci.yml job '${jobName}' setup-toolchain step`;
    const ref = step.uses.slice(step.uses.indexOf("@") + 1);
    // Exactly a 40-hex commit SHA - a tag, branch, or sha-with-suffix ref
    // is mutable and must not pass.
    if (!/^[0-9a-f]{40}$/.test(ref)) {
      fail(`${where} is not pinned to a full commit SHA (got '${ref}')`);
    }
    for (const tool of ["proto", "moon"] as const) {
      const wanted = pin(tool);
      const got = step.with?.[`${tool}-version`];
      if (typeof got !== "string" || got.length === 0) {
        fail(`${where} has no ${tool}-version input in its with: block (must pin it to ${wanted})`);
      } else if (got !== wanted) {
        fail(`${where} ${tool}-version (${got}) != .prototools ${tool} (${wanted})`);
      }
    }
  }
}
if (invocations === 0) {
  fail("ci.yml never uses moonrepo/setup-toolchain (expected the moon-running jobs to)");
}
console.log(
  `proto  ${pin("proto")} / moon ${pin("moon")} (${invocations} SHA-pinned ci.yml step(s))`,
);

// uv: pinned only in .prototools; just assert the pin exists.
console.log(`uv     ${pin("uv")} (.prototools is the single authority)`);

// python stays uv-owned: proto must not have the python plugin enabled.
const builtinPlugins = prototools.match(/builtin-plugins\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
if (!builtinPlugins) {
  fail(".prototools settings.builtin-plugins allow-list is missing (proto would provision python)");
} else if (/python/.test(builtinPlugins)) {
  fail(".prototools builtin-plugins includes python - python is owned by uv (.python-version)");
}

if (!failed) console.log("toolchain pins consistent");
process.exit(failed ? 1 : 0);
