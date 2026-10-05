#!/usr/bin/env bun
// Every task that runs bun or bunx must depend on root:install-deps (the root moon.yml header's first rule), so
// a task added without the edge fails here instead of on its first cold run. The header's second rule, the
// generated-contract mutex on every reader, has no mechanical census: which files a tool opens is not in the
// task graph, so that side stays a reviewed rule.

import { die, repoRoot } from "./lib.ts";

/** moon's resolved task graph (`moon query tasks`), project -> task id -> task; only the fields read here. */
export type TaskGraph = Record<
  string,
  Record<string, { command: string; script?: string | null; deps?: { target: string }[] }>
>;

/** The scripts whose contract is to run before or without an install (their headers say so), plus the install itself. */
export const INSTALL_FREE = new Set([
  "root:build-repro",
  "root:fuzz-smoke",
  "root:harness-smoke",
  "root:install-deps",
]);

// A script task's `command` is its first word (`set` for `set -e`), so each simple command of the script is
// split off at the shell operators and judged by its own first word; `echo bun` and a comment do not count.
const runsBun = (task: TaskGraph[string][string]): boolean =>
  /^bunx?$/.test(task.command) ||
  (task.script ?? "").split(/[\n;&|()]+/).some((command) =>
    /^bunx?$/.test(
      command
        .trim()
        .split(/\s+/)[0]
        ?.replace(/^["']|["']$/g, "") ?? "",
    ),
  );

export function missingInstallEdges(graph: TaskGraph, installFree = INSTALL_FREE): string[] {
  const missing: string[] = [];
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      if (installFree.has(target) || !runsBun(task)) continue;
      if (!(task.deps ?? []).some((dep) => dep.target === "root:install-deps"))
        missing.push(target);
    }
  }
  return missing.sort();
}

if (import.meta.main) {
  const query = Bun.spawnSync(["moon", "query", "tasks"], { cwd: repoRoot });
  if (!query.success) die(`moon query tasks failed: ${query.stderr.toString()}`);
  const { tasks } = JSON.parse(query.stdout.toString()) as { tasks?: TaskGraph };
  // The install task itself is the control: a graph without it, or with a record that is not a task, is a
  // misread, not a clean census.
  if (!tasks || Array.isArray(tasks) || !tasks.root?.["install-deps"]) {
    die(
      "moon query tasks returned no root:install-deps task; refusing to judge an unreadable graph",
    );
  }
  for (const [project, projectTasks] of Object.entries(tasks)) {
    for (const [id, task] of Object.entries(projectTasks)) {
      if (typeof task?.command !== "string")
        die(`${project}:${id} has no command; unreadable graph`);
    }
  }
  const missing = missingInstallEdges(tasks);
  if (missing.length > 0) {
    die(
      `tasks that run bun without depending on root:install-deps:\n${missing.map((t) => `  ${t}`).join("\n")}`,
    );
  }
  const total = Object.values(tasks).reduce((n, project) => n + Object.keys(project).length, 0);
  console.log(`check-moon-edges: every bun task depends on root:install-deps (${total} tasks)`);
}
