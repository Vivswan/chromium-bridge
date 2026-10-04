#!/usr/bin/env bun

// The next reader has the code, not the plan, so a comment or string may not point at a planning
// artifact: a numbered design record, a "decision N" or "finding N" tag, an audit code, a phase number.
// Each one is replaced by the reason it stood for, or deleted when the sentence already states the rule.
//
//   COVERED    -> git-tracked files under these globs are scanned; every match fails the gate
//   WAITING    -> files still carrying tags, each entry leaves with its tags (listed so the gate stays red
//                 on anything new while they wait)
//   not listed -> not scanned yet; widen COVERED when a tree is clean
//
// Usage: bun scripts/check-planning-refs.ts [repo-root]   (the root defaults to this checkout)

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse } from "@babel/parser";

export const COVERED: readonly string[] = [
  "src/apps/extension/**",
  "src/apps/web/**",
  "src/packages/shared/**",
  "tests/browser/**",
  "tests/harness/**",
  "docs/**",
  "README.md",
  "CONTRIBUTING.md",
];

export const WAITING: readonly string[] = [];

/** Line patterns, one per artifact kind. Each is written so this file's own text never matches it (the
 * record prefix goes through a character class, the examples carry no digit), which its test pins. A tag
 * may be hyphenated. A bare audit code (a letter or two and a digit) is flagged on a line only inside
 * parentheses, the shape the audit left behind; in prose the same letters name a heading or a key. */
export const PATTERNS: ReadonlyArray<readonly [name: string, re: RegExp]> = [
  ["design record number", /\b[A]DR-\d{4}\b/],
  ["bare design record word", /\b[A]DR\b/],
  ["retired records directory", /docs\/adr\//],
  ["decision tag", /\bdecisions?[ -]\d/],
  ["finding tag", /\bfindings?[ -]\d/],
  ["phase tag", /\bphase[ -]\d/i],
  ["audit code", /\b(?:E2F|D-P)-?\d/],
  ["parenthesized audit code", /\((?:CS|SFX|[HFUS])-?\d[a-z]?\)/],
];

/** A test title is where the bare codes were used as names, so there a code counts anywhere in the title.
 * Titles come from the parsed AST, never a regex: the call may carry modifiers (`test.each(cases)(`,
 * `it.skip(`), `.each`'s argument may hold calls, comments, and parentheses, a title may be a template
 * with nested templates in its holes, and the word `it` appears in prose. A file the parser rejects
 * fails the gate instead of being skipped. */
const TITLE_CALLS = new Set(["test", "describe", "it"]);
const TITLE_CODE = /\b(?:CS|SFX|[HFUS])-?\d[a-z]?\b/;
const TITLE_CODE_NAME = "audit code in a test title";
const SCRIPT_EXTENSIONS = /\.(?:[cm]?[jt]s|[jt]sx)$/;

type Node = { type: string; loc?: { start: { line: number } } } & Record<string, unknown>;

function titleOf(arg: Node | undefined): string | null {
  if (arg?.type === "StringLiteral") return arg.value as string;
  if (arg?.type === "TemplateLiteral") {
    const quasis = arg.quasis as Array<{ value: { cooked: string | null; raw: string } }>;
    return quasis.map((q) => q.value.cooked ?? q.value.raw).join(" ");
  }
  return null;
}

/** The leftmost identifier of a callee chain: `test.each(x)` and `it.skip` both resolve to the name. */
function calleeName(node: Node): string | null {
  let e = node;
  while (e.type === "MemberExpression" || e.type === "CallExpression") {
    e = (e.type === "MemberExpression" ? e.object : e.callee) as Node;
  }
  return e.type === "Identifier" ? (e.name as string) : null;
}

/** Every test/describe/it title in a script, with the 1-based line its title starts on. */
export function testTitles(path: string, text: string): Array<{ line: number; title: string }> {
  if (!SCRIPT_EXTENSIONS.test(path)) return [];
  let ast: Node;
  try {
    ast = parse(text, { sourceType: "module", plugins: ["typescript", "jsx"] }) as unknown as Node;
  } catch (e) {
    throw new Error(`${path}: cannot parse as TypeScript: ${(e as Error).message}`);
  }
  const found: Array<{ line: number; title: string }> = [];
  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child);
      return;
    }
    if (node === null || typeof node !== "object") return;
    const n = node as Node;
    if (n.type === "CallExpression" && TITLE_CALLS.has(calleeName(n.callee as Node) ?? "")) {
      const [first] = n.arguments as Node[];
      const title = titleOf(first);
      if (title !== null && first?.loc) found.push({ line: first.loc.start.line, title });
    }
    for (const [key, value] of Object.entries(n)) {
      if (key !== "loc" && key !== "start" && key !== "end") walk(value);
    }
  };
  walk(ast);
  return found;
}

export interface Hit {
  path: string;
  /** 1-based line number. */
  line: number;
  pattern: string;
  /** The offending line, trimmed. */
  text: string;
}

/** Scan one file's text. A line is reported once, under the first pattern it matches. */
export function findPlanningRefs(path: string, text: string): Hit[] {
  const lines = text.split("\n");
  const flagged = new Map<number, string>();
  lines.forEach((raw, index) => {
    const match = PATTERNS.find(([, re]) => re.test(raw));
    if (match) flagged.set(index, match[0]);
  });
  for (const { line, title } of testTitles(path, text)) {
    if (!TITLE_CODE.test(title)) continue;
    const index = line - 1;
    if (!flagged.has(index)) flagged.set(index, TITLE_CODE_NAME);
  }
  return [...flagged.entries()]
    .sort(([a], [b]) => a - b)
    .map(([index, pattern]) => ({
      path,
      line: index + 1,
      pattern,
      text: (lines[index] ?? "").trim(),
    }));
}

/** The environment for a git child aimed at a repository OTHER than the one a running git hook is
 * committing: the caller's, minus the GIT_* variables the hook exports (GIT_DIR, GIT_INDEX_FILE, ...).
 * Inherited, they would make `git -C <root>` read and WRITE the hook's repository instead of root. The
 * hook's own repository keeps them, so a commit built on an alternate index is scanned as staged. */
export function gitEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("GIT_")));
}

/** The git-tracked files under COVERED minus WAITING, repo-relative, sorted. git does the glob
 * matching, so an ignored build output or an untracked scratch file is never scanned. */
export function coveredFiles(root: string, env: NodeJS.ProcessEnv = process.env): string[] {
  const out = execFileSync("git", ["-C", root, "ls-files", "-z", "--", ...COVERED], {
    encoding: "utf8",
    env,
    maxBuffer: 64 * 1024 * 1024,
  });
  const waiting = new Set(WAITING);
  return out
    .split("\0")
    .filter((p) => p.length > 0 && !waiting.has(p))
    .sort();
}

export function scanFiles(root: string, paths: readonly string[]): Hit[] {
  return paths.flatMap((p) => findPlanningRefs(p, readFileSync(resolve(root, p), "utf8")));
}

function main(rootArg: string | undefined): number {
  const root = rootArg ? resolve(rootArg) : resolve(fileURLToPath(import.meta.url), "../..");
  const files = coveredFiles(root, rootArg ? gitEnv() : process.env);
  const hits = scanFiles(root, files);
  for (const hit of hits) {
    console.error(`${hit.path}:${hit.line}: ${hit.pattern}: ${hit.text}`);
  }
  if (hits.length > 0) {
    const files = new Set(hits.map((h) => h.path)).size;
    console.error(
      `check-planning-refs: ${hits.length} planning reference(s) in ${files} file(s). ` +
        "Replace each with the reason it stood for, or delete it when the sentence already states the rule.",
    );
    return 1;
  }
  const waiting = WAITING.length > 0 ? ` (${WAITING.length} waiting: ${WAITING.join(", ")})` : "";
  console.log(`check-planning-refs: ${files.length} file(s) clean${waiting}`);
  return 0;
}

if (import.meta.main) {
  process.exit(main(process.argv[2]));
}
