#!/usr/bin/env bun
// The front door: render every moon task with its description, grouped by
// project (the successor to `just --list`). Run via `moon run help`, or
// directly: `bun scripts/help.ts`. Raw JSON: `moon query tasks`.

import { repoRoot } from "./lib.ts";

const query = Bun.spawnSync(["moon", "query", "tasks"], { cwd: repoRoot });
if (query.exitCode !== 0) {
  console.error(query.stderr.toString());
  console.error("error: `moon query tasks` failed - is moon installed? (proto install)");
  process.exit(1);
}

interface TaskInfo {
  description?: string;
  command?: string;
  script?: string;
}
const parsed = JSON.parse(query.stdout.toString()) as {
  tasks: Record<string, Record<string, TaskInfo>>;
};

// Root first (it holds the repo-wide tasks and runbooks), then the projects.
const projects = Object.keys(parsed.tasks).sort((a, b) => {
  if (a === "root") return -1;
  if (b === "root") return 1;
  return a.localeCompare(b);
});

console.log("moon is the canonical command interface. Run a task: moon run <task>");
console.log("(unscoped names resolve to root; project tasks are <project>:<task>)\n");
for (const project of projects) {
  const tasks = parsed.tasks[project] ?? {};
  const names = Object.keys(tasks).sort();
  if (names.length === 0) continue;
  console.log(project === "root" ? "root (unscoped):" : `${project}:`);
  const width = Math.max(...names.map((name) => name.length)) + 2;
  for (const name of names) {
    const task = tasks[name] as TaskInfo;
    const summary = task.description ?? task.command ?? task.script ?? "";
    console.log(`  ${name.padEnd(width)}${summary.split("\n")[0]}`);
  }
  console.log("");
}
