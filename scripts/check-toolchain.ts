#!/usr/bin/env bun
// The toolchain pins that live in two files must agree, or local runs and CI use different tools:
//   rust  .prototools (what `proto install` pre-installs) vs rust-toolchain.toml, the authority: rustup,
//         IDEs, and CI read it, and it carries the components and profile proto cannot express
//   bun   .prototools vs package.json packageManager vs the template-managed .bun-version (what the
//         platform's bun jobs run)
// proto, moon, node, and uv are pinned in .prototools alone and CI reads them from there
// (.github/actions/setup-moon, the Containerfile). python stays uv's (.python-version): proto's plugin
// allow-list must not name it, or two provisioners own one interpreter.
//
// Run via `moon run check-toolchain` (part of the ci gate).

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

const rustToolchain = readFileSync(join(repoRoot, "rust-toolchain.toml"), "utf8");
const channel = rustToolchain.match(/^channel\s*=\s*"([^"]+)"/m)?.[1];
if (!channel) {
  fail("rust-toolchain.toml has no channel pin");
} else if (pin("rust") !== channel) {
  fail(`.prototools rust (${pin("rust")}) != rust-toolchain.toml channel (${channel})`);
}
console.log(`rust   ${channel ?? "<missing>"} (authority: rust-toolchain.toml)`);

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

const bunVersionFile = readFileSync(join(repoRoot, ".bun-version"), "utf8").trim();
if (bunVersionFile !== pin("bun")) {
  fail(`.prototools bun (${pin("bun")}) != .bun-version (${bunVersionFile})`);
}
console.log(`bun    ${bunVersionFile} (.bun-version, template-managed)`);

const builtinPlugins = prototools.match(/builtin-plugins\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
if (!builtinPlugins) {
  fail(".prototools settings.builtin-plugins allow-list is missing (proto would provision python)");
} else if (/python/.test(builtinPlugins)) {
  fail(".prototools builtin-plugins includes python - python is owned by uv (.python-version)");
}

if (!failed) console.log("toolchain pins consistent");
process.exit(failed ? 1 : 0);
