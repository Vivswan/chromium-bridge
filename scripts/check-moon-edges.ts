#!/usr/bin/env bun
// The root moon.yml header's first four rules, read back from moon's resolved task graph so a task added without
// them fails here instead of on its first cold run, inside a commit, or against a stale artifact. The other two
// have no mechanical census: what a script spawns and which files a tool opens are not in the task graph.

import { posix } from "node:path";
import { type ParseEntry, parse } from "shell-quote";
import { die, repoRoot } from "./lib.ts";

/** moon's resolved task graph (`moon query tasks`), project -> task id -> task; only the fields read here. */
export type TaskGraph = Record<
  string,
  Record<
    string,
    {
      command: string;
      args?: string[] | null;
      script?: string | null;
      deps?: { target: string }[];
      env?: Record<string, string> | null;
      options?: { runFromWorkspaceRoot?: boolean } | null;
      inputFiles?: Record<string, unknown> | null;
      inputGlobs?: Record<string, unknown> | null;
      outputFiles?: Record<string, unknown> | null;
      outputGlobs?: Record<string, unknown> | null;
    }
  >
>;
type Task = TaskGraph[string][string];

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

// bun's global options may or may not take a value (`--config` accepts an omitted one), so no table of them is
// trusted: like the installer rule, the alias rule reads every word, and `x` anywhere in a bun command is bunx.
const unalias = (words: string[]): string[] => {
  const x = words[0] === "bun" ? words.indexOf("x") : -1;
  return x === -1 ? words : ["bunx", ...words.slice(x + 1)];
};

/** Operators that end a simple command; `<(` and `(` open a nested one, whose words are its own command. */
const SEPARATORS = new Set([";", ";;", "&", "&&", "|", "|&", "||", "(", ")", "<("]);

// shell-quote parses one command line: a newline separates nothing and a `#` runs to the end of the text, so the
// script is split into lines first, after joining `\`-continued ones. A variable is kept by name in braces, since
// moon has already substituted its own tokens and a shell variable's value is not the auditor's to guess. A
// redirection's file stays a word: the command reads or writes it, which is what the build/ rule asks.
function simpleCommands(task: Task): string[][] {
  if (task.script == null) return [unalias([task.command, ...(task.args ?? [])])];
  const commands: string[][] = [];
  for (const line of task.script.replace(/\\\n/g, "").split("\n")) {
    let words: string[] = [];
    const entries: ParseEntry[] = parse(line, (name) => `\${${name}}`);
    for (const entry of entries) {
      if (typeof entry === "string") {
        words.push(entry);
      } else if ("comment" in entry) {
        break;
      } else if (entry.op === "glob") {
        words.push(entry.pattern);
      } else if (SEPARATORS.has(entry.op)) {
        if (words.length > 0) commands.push(unalias(words));
        words = [];
      }
    }
    if (words.length > 0) commands.push(unalias(words));
  }
  return commands;
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

const BUILD_DIR = "build";
const ROOT_PROJECT = GATE.split(":")[0];

const under = (dir: string, path: string): boolean => path === dir || path.startsWith(`${dir}/`);
const normalized = (path: string): string => posix.normalize(path).replace(/\/$/, "");

// Only plain paths are judged, and a glob under build/ on either side is a finding: the repository's artifacts
// are directories, and matching a reader's glob against a writer's is a semantics this rule does not take on.
const buildGlobs = (globs: Record<string, unknown> | null | undefined): string[] =>
  Object.keys(globs ?? {}).filter((glob) => under(BUILD_DIR, glob.split(/[*?[{]/)[0] ?? ""));

// A declared input is workspace-relative in the resolved graph, so it counts for every task. A command word is
// relative to the task's cwd, so it counts only when that is the workspace root, and only as a relative path:
// `/build/x` is a filesystem path, `build` alone is a task or script name. What a script opens is not in the
// graph, so a read the task does not declare stays invisible here.
const namedBuildPaths = (project: string, task: Task, commands: string[][]): string[] => {
  const atRoot = project === ROOT_PROJECT || task.options?.runFromWorkspaceRoot === true;
  const words = atRoot
    ? commands.flat().filter((word) => posix.normalize(word).startsWith(`${BUILD_DIR}/`))
    : [];
  const inputs = Object.keys(task.inputFiles ?? {});
  return [...new Set([...words, ...inputs].map(normalized))].filter((path) =>
    under(BUILD_DIR, path),
  );
};

function buildWriters(graph: TaskGraph): { target: string; dir: string }[] {
  const writers: { target: string; dir: string }[] = [];
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      for (const output of Object.keys(task.outputFiles ?? {}).map(normalized)) {
        if (under(BUILD_DIR, output)) writers.push({ target: `${project}:${id}`, dir: output });
      }
    }
  }
  return writers;
}

export function auditGraph(graph: TaskGraph): string[] {
  const findings: string[] = [];
  const writers = buildWriters(graph);
  // A script shell-quote refuses is a finding against its task, and that task has no commands to judge.
  const commandsOf = new Map<string, string[][]>();
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      try {
        commandsOf.set(target, simpleCommands(task));
      } catch (error) {
        findings.push(`${target}: unparsable script (${(error as Error).message})`);
        commandsOf.set(target, []);
      }
    }
  }
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      const commands = commandsOf.get(target) ?? [];
      if (commands.some(([word]) => word === "bunx")) {
        findings.push(`${target}: runs bunx (bun's global cache stands in for a missing package)`);
      }
      for (const glob of buildGlobs(task.inputGlobs)) {
        findings.push(
          `${target}: declares the glob input ${glob}; a reader under build/ declares the file or directory it reads`,
        );
      }
      for (const glob of buildGlobs(task.outputGlobs)) {
        findings.push(
          `${target}: declares the glob output ${glob}; a writer under build/ declares the directory it writes`,
        );
      }
      for (const path of namedBuildPaths(project, task, commands)) {
        // A writer of the path or a directory above it, and every writer inside a directory the task names.
        const covering = writers.filter(
          (writer) => under(writer.dir, path) || under(path, writer.dir),
        );
        if (covering.length === 0) {
          findings.push(`${target}: names ${path}, which no task's outputs write`);
          continue;
        }
        const ordered = new Set(closure(graph, target).reached);
        for (const writer of covering) {
          if (writer.target !== target && !ordered.has(writer.target)) {
            findings.push(
              `${target}: names ${path} without depending on ${writer.target}, which writes ${writer.dir}`,
            );
          }
        }
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
    for (const words of commandsOf.get(target) ?? []) {
      const [word, ...rest] = words;
      const installer = word === "bun" ? rest.find((w) => BUN_INSTALLERS.has(w)) : undefined;
      if (installer !== undefined) {
        findings.push(`${target}: bun ${installer} inside ${GATE} (installs)`);
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
      // Past cargo's `--` the words belong to the tool it runs, so a --frozen there is not cargo's.
      const cargoArgs = rest.includes("--") ? rest.slice(0, rest.indexOf("--")) : rest;
      if (verb !== "fmt" && !cargoArgs.includes("--frozen")) {
        findings.push(`${target}: cargo ${verb} inside ${GATE} without --frozen`);
      }
      if (task.env?.RUSTUP_AUTO_INSTALL !== "0") {
        findings.push(
          `${target}: cargo ${verb} inside ${GATE} without RUSTUP_AUTO_INSTALL=0 in env`,
        );
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
    `check-moon-edges: no bunx, ${GATE} runs only the repository's own toolchain, and every named build/ path follows its writer (${total} tasks)`,
  );
}
