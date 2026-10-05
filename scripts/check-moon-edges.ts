#!/usr/bin/env bun
// The root moon.yml header's first two rules (the check-deps edge and --no-install for bun; the gate's closure
// confined to the repository's own toolchain, with the check-crates edge and --frozen on its cargo verbs), read
// from moon's resolved task graph so a task added without them fails here instead of on its first cold run or
// inside a commit. The mutex rule has no mechanical census: which files a tool opens is not in the task graph.

import { die, repoRoot } from "./lib.ts";

/** moon's resolved task graph (`moon query tasks`), project -> task id -> task; only the fields read here. */
export type TaskGraph = Record<
  string,
  Record<
    string,
    { command: string; args?: string[] | null; script?: string | null; deps?: { target: string }[] }
  >
>;

export const DEPS_CHECK = "root:check-deps";
export const CRATES_CHECK = "root:check-crates";
export const GATE = "root:gate";

/** bun subcommands that install or change what is installed, aliases included (`bun i`, `bun a`, `bun rm`). */
const BUN_INSTALLERS = new Set([
  "install",
  "i",
  "add",
  "a",
  "remove",
  "rm",
  "update",
  "link",
  "pm",
]);

/** cargo verbs the pinned toolchain ships, plus nextest, the test runner docs/development.md installs once. */
export const TOOLCHAIN_CARGO_VERBS = new Set([
  "build",
  "check",
  "clippy",
  "doc",
  "fetch",
  "fmt",
  "nextest",
  "run",
  "test",
  "tree",
]);

/**
 * The bun tasks without the check-deps edge: the scripts whose contract is to run before or without an install
 * (their headers say so), the install itself, and its two checks.
 */
export const EDGE_EXEMPT = new Set([
  "root:build-repro",
  "root:fuzz-smoke",
  "root:harness-smoke",
  "root:setup",
  DEPS_CHECK,
  CRATES_CHECK,
]);

// A script task's `command` is its first word (`set` for `set -e`), so the script is cut into simple commands at
// the shell operators (backslash continuations joined first, comments dropped); a command task is one command.
// `bun x` is bunx by another spelling, so both rules see one form.
const unalias = (words: string[]): string[] =>
  words[0] === "bun" && words[1] === "x" ? ["bunx", ...words.slice(2)] : words;

function simpleCommands(task: TaskGraph[string][string]): string[][] {
  if (task.script == null) return [unalias([task.command, ...(task.args ?? [])])];
  return task.script
    .replace(/\\\n\s*/g, " ")
    .split(/[\n;&|()]+/)
    .map((command) =>
      command
        .trim()
        .split(/\s+/)
        .map((word) => word.replace(/^["']|["']$/g, ""))
        .filter((word) => word.length > 0),
    )
    .filter((words) => words.length > 0 && !words[0]?.startsWith("#"))
    .map(unalias);
}

const dependsOn = (task: TaskGraph[string][string], target: string): boolean =>
  (task.deps ?? []).some((dep) => dep.target === target);

function closure(graph: TaskGraph, start: string): { reached: string[]; unknown: string[] } {
  const reached = new Set<string>();
  const unknown = new Set<string>();
  const pending = [start];
  for (let target = pending.pop(); target !== undefined; target = pending.pop()) {
    if (reached.has(target)) continue;
    const [project, id] = target.split(":");
    const task = project !== undefined && id !== undefined ? graph[project]?.[id] : undefined;
    if (task === undefined) {
      unknown.add(target);
      continue;
    }
    reached.add(target);
    for (const dep of task.deps ?? []) pending.push(dep.target);
  }
  return { reached: [...reached], unknown: [...unknown] };
}

export function auditGraph(graph: TaskGraph, exempt = EDGE_EXEMPT): string[] {
  const findings: string[] = [];
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      const commands = simpleCommands(task);
      const runsBun = commands.some(([word]) => word === "bun" || word === "bunx");
      if (runsBun && !exempt.has(target) && !dependsOn(task, DEPS_CHECK)) {
        findings.push(`${target}: runs bun without depending on ${DEPS_CHECK}`);
      }
      if (commands.some(([word, flag]) => word === "bunx" && flag !== "--no-install")) {
        findings.push(`${target}: bunx without --no-install`);
      }
    }
  }
  const gate = closure(graph, GATE);
  for (const target of gate.unknown)
    findings.push(`${target}: reachable from ${GATE} but not in the graph`);
  for (const target of gate.reached) {
    const [project, id] = target.split(":") as [string, string];
    const task = graph[project]?.[id];
    if (task === undefined) continue;
    for (const [word, ...rest] of simpleCommands(task)) {
      if (word === "bun" && BUN_INSTALLERS.has(rest[0] ?? "")) {
        findings.push(`${target}: bun ${rest[0]} inside ${GATE} (installs)`);
      }
      // `noop` is moon's placeholder command for a dependency-only aggregate.
      if (word === "bun" || word === "bunx" || word === "set" || word === "noop") continue;
      if (word !== "cargo") {
        findings.push(
          `${target}: runs ${word} inside ${GATE} (not bun, bunx, or a cargo toolchain verb)`,
        );
        continue;
      }
      const verb = rest[0] ?? "";
      if (!TOOLCHAIN_CARGO_VERBS.has(verb)) {
        findings.push(`${target}: runs cargo ${verb} inside ${GATE} (not a toolchain verb)`);
      }
      if (!dependsOn(task, CRATES_CHECK)) {
        findings.push(`${target}: runs cargo inside ${GATE} without depending on ${CRATES_CHECK}`);
      }
      if (verb !== "fmt" && !rest.includes("--frozen")) {
        findings.push(`${target}: cargo ${verb} inside ${GATE} without --frozen`);
      }
    }
  }
  return findings.sort();
}

if (import.meta.main) {
  const query = Bun.spawnSync(["moon", "query", "tasks"], { cwd: repoRoot });
  if (!query.success) die(`moon query tasks failed: ${query.stderr.toString()}`);
  const { tasks } = JSON.parse(query.stdout.toString()) as { tasks?: TaskGraph };
  // The check tasks and the gate are the control: a graph without them, or with a record that is not a task,
  // is a misread, not a clean census.
  if (
    !tasks ||
    Array.isArray(tasks) ||
    !tasks.root?.["check-deps"] ||
    !tasks.root?.["check-crates"] ||
    !tasks.root?.gate
  ) {
    die(
      `moon query tasks returned no ${DEPS_CHECK}, ${CRATES_CHECK}, or ${GATE} task; refusing to judge an unreadable graph`,
    );
  }
  for (const [project, projectTasks] of Object.entries(tasks)) {
    for (const [id, task] of Object.entries(projectTasks)) {
      if (typeof task?.command !== "string")
        die(`${project}:${id} has no command; unreadable graph`);
    }
  }
  const findings = auditGraph(tasks);
  if (findings.length > 0) {
    die(`tasks breaking the moon.yml header's rules:\n${findings.map((f) => `  ${f}`).join("\n")}`);
  }
  const total = Object.values(tasks).reduce((n, project) => n + Object.keys(project).length, 0);
  console.log(
    `check-moon-edges: bun tasks depend on ${DEPS_CHECK}, and ${GATE} runs only the repository's own toolchain (${total} tasks)`,
  );
}
