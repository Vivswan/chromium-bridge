#!/usr/bin/env bun
// The one reader of a toolchain pin for the consumers that run before proto exists (the setup-moon
// composite on a bare runner, the container-image workflow computing the image's build arg, the compose
// launcher building the image locally) and for checks.yml's tooling job. Each tool is pinned in exactly
// one of two owner files, and a pin found in both, twice, or nowhere is refused instead of one consumer
// quietly picking a copy.
//
//   .prototools    proto = "0.58.2"                  -> bun scripts/pin.ts proto
//   Containerfile  ARG CARGO_MACHETE_VERSION=0.9.2    -> bun scripts/pin.ts cargo-machete
//   every pin of both files through the same rule    -> bun scripts/pin.ts --all   (moon run check-pins)
//
// .prototools goes through Bun's TOML parser, which already refuses a repeated key (indented or not) and
// keeps a key under [settings] out of the root. The Containerfile is scanned as text because Docker lets
// the last of two ARG lines win silently, indented or not, and only a raw count can see the first.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

export const ownerFiles = [".prototools", "Containerfile"] as const;

const toolName = /^[a-z][a-z0-9-]*$/;
const argLine = /^\s*ARG\s+([A-Z][A-Z0-9_]*)_VERSION=(\S*)\s*$/;

function owned(root: string, file: (typeof ownerFiles)[number]): string {
  try {
    return readFileSync(join(root, file), "utf8");
  } catch (error) {
    throw new Error(`pin: cannot read ${file} (${(error as Error).message})`);
  }
}

function prototoolsRoot(text: string): Record<string, unknown> {
  try {
    return Bun.TOML.parse(text) as Record<string, unknown>;
  } catch (error) {
    throw new Error(`pin: .prototools is not valid TOML (${(error as Error).message})`);
  }
}

function prototoolsPins(root: Record<string, unknown>, tool: string): string[] {
  if (!(tool in root)) return [];
  const value = root[tool];
  if (typeof value !== "string" || value === "") {
    throw new Error(`pin: .prototools pins ${tool} to an empty or non-string value`);
  }
  return [value];
}

// ARG lines keyed by the tool they pin: CARGO_MACHETE_VERSION -> cargo-machete. An ARG with no `=` (the
// Containerfile's own PROTO_VERSION build arg) declares a consumer, not a pin.
function containerfileArgs(text: string): [string, string][] {
  const pins: [string, string][] = [];
  for (const line of text.split("\n")) {
    const match = line.match(argLine);
    if (!match) continue;
    const tool = (match[1] as string).toLowerCase().replaceAll("_", "-");
    const value = match[2] as string;
    if (value === "") throw new Error(`pin: Containerfile pins ${tool} to an empty value`);
    pins.push([tool, value]);
  }
  return pins;
}

function resolve(
  tool: string,
  prototools: Record<string, unknown>,
  args: [string, string][],
): string {
  const pins = [
    ...prototoolsPins(prototools, tool),
    ...args.filter(([name]) => name === tool).map(([, value]) => value),
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

export function readPin(tool: string, root = repoRoot): string {
  if (!toolName.test(tool)) throw new Error(`pin: not a tool name: ${tool}`);
  return resolve(
    tool,
    prototoolsRoot(owned(root, ".prototools")),
    containerfileArgs(owned(root, "Containerfile")),
  );
}

// Every tool either file pins, each through the one-owner rule, so a second owner added for a tool no
// CI step asks for by name is still refused.
export function readAllPins(root = repoRoot): Map<string, string> {
  const prototools = prototoolsRoot(owned(root, ".prototools"));
  const args = containerfileArgs(owned(root, "Containerfile"));
  const tools = new Set<string>([
    ...Object.entries(prototools)
      .filter(([, value]) => typeof value !== "object")
      .map(([key]) => key),
    ...args.map(([tool]) => tool),
  ]);
  for (const tool of tools) {
    if (!toolName.test(tool)) throw new Error(`pin: not a tool name: ${tool}`);
  }
  return new Map([...tools].sort().map((tool) => [tool, resolve(tool, prototools, args)]));
}

if (import.meta.main) {
  const tool = process.argv[2];
  if (!tool || process.argv.length !== 3) {
    console.error("usage: bun scripts/pin.ts <tool> | --all");
    process.exit(2);
  }
  try {
    if (tool === "--all") {
      for (const [name, version] of readAllPins()) console.log(`${name} ${version}`);
    } else {
      console.log(readPin(tool));
    }
  } catch (error) {
    console.error((error as Error).message);
    process.exit(1);
  }
}
