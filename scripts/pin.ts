#!/usr/bin/env bun
// The one reader of a toolchain pin for the consumers that run before proto exists (the setup-moon
// composite on a bare runner, the container-image workflow computing the image's build arg, the compose
// launcher building the image locally) and for checks.yml's tooling job. Each tool is pinned in exactly
// one of two owner files, and a pin found in both, twice, or nowhere is refused instead of one consumer
// quietly picking a copy.
//
//   .prototools    proto = "0.58.2"                  -> bun scripts/pin.ts proto
//   Containerfile  ARG CARGO_MACHETE_VERSION=0.9.2    -> bun scripts/pin.ts cargo-machete
//
// .prototools goes through Bun's TOML parser, which already refuses a repeated key (indented or not) and
// keeps a key under [settings] out of the root. The Containerfile is scanned as text because Docker lets
// the last of two ARG lines win silently, indented or not, and only a raw count can see the first.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

export const ownerFiles = [".prototools", "Containerfile"] as const;

function owned(root: string, file: (typeof ownerFiles)[number]): string {
  try {
    return readFileSync(join(root, file), "utf8");
  } catch (error) {
    throw new Error(`pin: cannot read ${file} (${(error as Error).message})`);
  }
}

function prototoolsPins(text: string, tool: string): string[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = Bun.TOML.parse(text) as Record<string, unknown>;
  } catch (error) {
    throw new Error(`pin: .prototools is not valid TOML (${(error as Error).message})`);
  }
  if (!(tool in parsed)) return [];
  const value = parsed[tool];
  if (typeof value !== "string") throw new Error(`pin: .prototools pins ${tool} to a non-string`);
  return [value];
}

function containerfilePins(text: string, tool: string): string[] {
  const arg = `${tool.toUpperCase().replaceAll("-", "_")}_VERSION`;
  const instruction = new RegExp(`^\\s*ARG\\s+${arg}=(\\S+)\\s*$`);
  return text
    .split("\n")
    .map((line) => line.match(instruction)?.[1])
    .filter((pin): pin is string => pin !== undefined);
}

export function readPin(tool: string, root = repoRoot): string {
  if (!/^[a-z][a-z0-9-]*$/.test(tool)) throw new Error(`pin: not a tool name: ${tool}`);
  const pins = [
    ...prototoolsPins(owned(root, ".prototools"), tool),
    ...containerfilePins(owned(root, "Containerfile"), tool),
  ];
  if (pins.length === 0)
    throw new Error(`pin: ${tool} is pinned in neither ${ownerFiles.join(" nor ")}`);
  if (pins.length > 1) {
    throw new Error(
      `pin: ${tool} is pinned more than once (one owner per pin): ${pins.join(", ")}`,
    );
  }
  return pins[0] as string;
}

if (import.meta.main) {
  const tool = process.argv[2];
  if (!tool || process.argv.length !== 3) {
    console.error("usage: bun scripts/pin.ts <tool>");
    process.exit(2);
  }
  try {
    console.log(readPin(tool));
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
}
