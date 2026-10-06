#!/usr/bin/env bun
// The one toolchain pin that lives in two files must agree, or local runs and CI use different tools:
//   bun   .prototools vs package.json packageManager vs the template-managed .bun-version (what the
//         platform's bun jobs run)
// proto, moon, node, and uv are pinned in .prototools alone and CI reads them from there
// (.github/actions/setup-moon, the Containerfile); rust is pinned in rust-toolchain.toml alone. python
// stays uv's (.python-version) and rust stays rustup's: proto's plugin allow-list must name neither, or
// two provisioners own one tool.
//
// Run via `moon run check-toolchain` (part of the ci gate).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

/** Every disagreement among the pins under `root`, one line each; empty when the copies agree. */
export function toolchainMismatches(root: string): string[] {
  const mismatches: string[] = [];
  const fail = (message: string): void => {
    mismatches.push(message);
  };
  const read = (file: string): string => readFileSync(join(root, file), "utf8");

  const prototools = read(".prototools");
  // Pins live above the first [table]; a simple key = "value" scan suffices.
  const pins = new Map<string, string>();
  for (const line of prototools.split("\n")) {
    if (line.startsWith("[")) break;
    const match = line.match(/^([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"/);
    if (match) pins.set(match[1] as string, match[2] as string);
  }
  const bunPin = pins.get("bun") ?? "<missing>";
  if (!pins.has("bun")) fail(".prototools does not pin bun");

  const rootPkg = JSON.parse(read("package.json")) as { packageManager?: string };
  const packageManager = rootPkg.packageManager ?? "";
  const bunFromPkg = packageManager.match(/^bun@(.+)$/)?.[1];
  if (!bunFromPkg) {
    fail(`package.json packageManager (${packageManager}) is not a bun pin`);
  } else if (bunPin !== bunFromPkg) {
    fail(`.prototools bun (${bunPin}) != package.json packageManager (${bunFromPkg})`);
  }

  const bunVersionFile = read(".bun-version").trim();
  if (bunVersionFile !== bunPin) {
    fail(`.prototools bun (${bunPin}) != .bun-version (${bunVersionFile})`);
  }

  if (pins.has("rust")) {
    fail(
      ".prototools pins rust - rust-toolchain.toml is its only pin (proto's install breaks rustup's)",
    );
  }
  const builtinPlugins = prototools.match(/builtin-plugins\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
  if (!builtinPlugins) {
    fail(
      ".prototools settings.builtin-plugins allow-list is missing (proto would provision python and rust)",
    );
  } else {
    for (const tool of ["python", "rust"]) {
      if (builtinPlugins.includes(tool)) {
        fail(
          `.prototools builtin-plugins includes ${tool} - ${tool === "python" ? "python is owned by uv (.python-version)" : "rust is owned by rustup (rust-toolchain.toml)"}`,
        );
      }
    }
  }
  return mismatches;
}

if (import.meta.main) {
  const mismatches = toolchainMismatches(repoRoot);
  for (const mismatch of mismatches) console.error(`MISMATCH: ${mismatch}`);
  if (mismatches.length === 0) console.log("toolchain pins consistent");
  process.exit(mismatches.length === 0 ? 0 : 1);
}
