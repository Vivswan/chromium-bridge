#!/usr/bin/env bun
// The root moon.yml header's first three rules, read back from moon's resolved task graph so a task added without
// them fails here instead of on its first cold run or inside a commit. The other two have no mechanical census:
// what a script spawns and which files a tool opens are not in the task graph.

import { die, repoRoot } from "./lib.ts";

/** moon's resolved task graph (`moon query tasks`), project -> task id -> task; only the fields read here. */
export type TaskGraph = Record<
  string,
  Record<
    string,
    { command: string; args?: string[] | null; script?: string | null; deps?: { target: string }[] }
  >
>;

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

// `bun x` is bunx by another spelling, so the rule sees one form.
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

export function auditGraph(graph: TaskGraph): string[] {
  const findings: string[] = [];
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      // bunx answers from bun's global cache by bare name when node_modules is absent; `bun run <bin>` does not.
      if (simpleCommands(task).some(([word]) => word === "bunx")) {
        findings.push(`${target}: runs bunx (bun's global cache stands in for a missing package)`);
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
      if (word === "bun" || word === "set" || word === "noop") continue;
      if (word !== "cargo") {
        findings.push(`${target}: runs ${word} inside ${GATE} (not bun or a cargo toolchain verb)`);
        continue;
      }
      const verb = rest[0] ?? "";
      if (!TOOLCHAIN_CARGO_VERBS.has(verb)) {
        findings.push(`${target}: runs cargo ${verb} inside ${GATE} (not a toolchain verb)`);
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
  // The gate is the control: a graph without it, or with a record that is not a task, is a misread, not a
  // clean census.
  if (!tasks || Array.isArray(tasks) || !tasks.root?.gate) {
    die(`moon query tasks returned no ${GATE} task; refusing to judge an unreadable graph`);
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
    `check-moon-edges: no bunx, and ${GATE} runs only the repository's own toolchain (${total} tasks)`,
  );
}
