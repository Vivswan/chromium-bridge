#!/usr/bin/env bun
// The root moon.yml header's first four rules, read back from moon's resolved task graph so a task added without
// them fails here instead of on its first cold run, inside a commit, or against a stale artifact. The other two
// have no mechanical census: what a script spawns and which files a tool opens are not in the task graph.

import { posix } from "node:path";
import type * as Sh from "mvdan-sh";
import sh from "mvdan-sh";
import { die, repoRoot } from "./lib.ts";

/** The published types allow a null in every node list the parser never leaves one in. */
const present = <T>(nodes: (T | null)[]): T[] => nodes.filter((node): node is T => node !== null);

/** What Parser.Parse throws, a Go error the published types leave out. */
interface ParseError {
  Filename: string;
  Text: string;
  Incomplete: boolean;
  Error: () => string;
}

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

// A script word as the shell reads it. A glob keeps the text before its first live pattern character, which
// is all the build/ rule may judge: a quoted `*` earlier in the word is text, not where the pattern starts. A
// word with an expansion in it is not literal: its text is a marker, and the gate's rule refuses what it
// cannot read. An extglob is opaque besides: the parser keeps its pattern as text, so a command inside it is
// unread anywhere, and every task refuses it.
type Reading = "literal" | "expansion" | "opaque";
const RANK: Record<Reading, number> = { literal: 0, expansion: 1, opaque: 2 };
const worst = (a: Reading, b: Reading): Reading => (RANK[a] >= RANK[b] ? a : b);
interface Word {
  text: string;
  globPrefix: string | null;
  reading: Reading;
}

// What the gate's rule judges: a simple command's words after the assignments before its name, with those
// assignments' names, or a compound command as the one word of its keyword.
interface Command {
  words: Word[];
  assigns: string[];
}

// A path is named outside a command too (`[[ -f build/x ]]`, `for f in build/*`, `X=build/y`), so the path
// rules read every word of the script, while the command rules read the commands. The words the shell reads
// as data (a heredoc's body and delimiter, a here-string, a descriptor) name no path, but an expansion in
// one still runs, so the gate's literal rule reads them too.
interface Commands {
  commands: Command[];
  words: Word[];
  data: Word[];
}

const GLOB_CHAR = /[*?[{]/;

/** A word moon passes as one argument, or one of its own globs: no shell reads it, so a backslash is itself. */
const asWord = (text: string): Word => {
  const at = text.search(GLOB_CHAR);
  return { text, globPrefix: at === -1 ? null : text.slice(0, at), reading: "literal" };
};

// A backslash quotes the next character, so `in\stall` is `install` and `\*` is no glob, while `\\*` is a
// backslash and a glob. Inside double quotes only `\`, `"`, `$`, and a backquote can be quoted that way. A
// brace the shell reads opens an expansion whose forms the rules do not read (`{a,b}`, `{1..9..2}`, `{x..Z}`),
// so it makes the word non-literal; the parser keeps it inside the literal.
function literal(raw: string, quoted: boolean): Word {
  let text = "";
  let globPrefix: string | null = null;
  let reading: Reading = "literal";
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i] as string;
    const next = raw[i + 1];
    if (c === "\\" && next !== undefined && (!quoted || '\\"$`'.includes(next))) {
      text += next;
      i++;
      continue;
    }
    if (!quoted && globPrefix === null && GLOB_CHAR.test(c)) globPrefix = text;
    if (!quoted && c === "{") reading = "expansion";
    text += c;
  }
  return { text, globPrefix, reading };
}

// bun's global options may or may not take a value (`--config` accepts an omitted one), so no table of them is
// trusted: like the installer rule, the alias rule reads every word, and `x` or `bunx` anywhere in a bun command
// is bunx (`bun x`, `bun run bunx`, which runs the bunx on PATH).
const unalias = (words: Word[]): Word[] => {
  const x =
    words[0]?.text === "bun" ? words.findIndex((w) => w.text === "x" || w.text === "bunx") : -1;
  return x === -1 ? words : [asWord("bunx"), ...words.slice(x + 1)];
};

// A launcher runs one of its arguments as a command, and which one depends on options this rule does not model
// (`env -i X=1`, `nice -n 5`, `exec -a name`, `env -u bun`), so, as with bun's own options, the bunx rule reads
// every word after the launcher: a bunx, or a bun with an x after it. Every name is its basename, so
// `/usr/bin/env` is env and `/opt/homebrew/bin/bunx` is bunx, and a bun by path, which unalias leaves as the
// gate's rules refuse it, has its x read here; bare `time` is a keyword the parser opens itself. The gate's
// rules see the launcher as the command, and refuse it by name.
const LAUNCHERS = new Set([
  "builtin",
  "command",
  "env",
  "exec",
  "nice",
  "nohup",
  "time",
  "timeout",
  "xargs",
]);
const runsBunx = (words: Word[]): boolean => {
  const [first, ...rest] = words.map((w) => posix.basename(w.text));
  if (first === "bunx") return true;
  if (first === "bun") return rest.includes("x") || rest.includes("bunx");
  if (first === undefined || !LAUNCHERS.has(first)) return false;
  const bun = rest.indexOf("bun");
  return rest.includes("bunx") || (bun !== -1 && rest.includes("x", bun + 1));
};

const { syntax } = sh;
const parser = syntax.NewParser();

// Redirect.Op is syntax.RedirOperator's number in the JS build, Go's iota order from token.go (the published
// types declare a RedirOperator table the bundle does not export): `<<` and `<<-` take a delimiter and `<<<` a
// string, data the rules read for an expansion only. Every other operator's word is a file; a descriptor dup's
// number (`2>&1`) is then a word no rule has anything to say about.
const NOT_A_FILE = new Set([61, 62, 63]);
const namesFile = (redirect: Sh.Redirect): boolean => !NOT_A_FILE.has(redirect.Op);

// A variable is kept by name in braces: moon has already substituted its own tokens, and a shell variable's
// value is not the auditor's to guess. A substitution's commands are walked as their own, so the word that
// holds one is a marker.
function render(part: Sh.Node, quoted: boolean): Word {
  switch (syntax.NodeType(part)) {
    case "Lit":
      return literal((part as Sh.Lit).Value, quoted);
    // ANSI-C quoting (`$'...'`) decodes escapes the rules do not read, so `$'in\x73tall'` is not `install` here.
    case "SglQuoted": {
      const { Dollar, Value } = part as Sh.SglQuoted;
      return {
        text: Dollar ? `$'${Value}'` : Value,
        globPrefix: null,
        reading: Dollar ? "expansion" : "literal",
      };
    }
    case "DblQuoted": {
      const parts = (part as Sh.DblQuoted).Parts.map((p) => render(p, true));
      return {
        text: parts.map((p) => p.text).join(""),
        globPrefix: null,
        reading: parts.map((p) => p.reading).reduce(worst, "literal"),
      };
    }
    case "ParamExp":
      return {
        text: `\${${(part as Sh.ParamExp).Param?.Value ?? ""}}`,
        globPrefix: null,
        reading: "expansion",
      };
    // The parser keeps an extglob's pattern as text, so a substitution inside it is unread.
    case "ExtGlob":
      return {
        text: `(${(part as Sh.ExtGlob).Pattern?.Value ?? ""})`,
        globPrefix: quoted ? null : "",
        reading: "opaque",
      };
    case "CmdSubst":
      return { text: "$(...)", globPrefix: null, reading: "expansion" };
    case "ProcSubst":
      return { text: "<(...)", globPrefix: null, reading: "expansion" };
    case "ArithmExp":
      return { text: "$((...))", globPrefix: null, reading: "expansion" };
    default:
      return { text: `<${syntax.NodeType(part)}>`, globPrefix: null, reading: "expansion" };
  }
}

// A data word (a heredoc's body or delimiter, a here-string) reads as quoted text: bash expands no brace and
// matches no glob there. Its backslashes follow double quotes' rule, which a heredoc body and a
// here-string each bend a little; the text reaches only a finding's message.
const wordOf = (w: Sh.Word, quoted = false): Word =>
  w.Parts.map((part) => render(part, quoted)).reduce(
    (acc, part) => ({
      text: acc.text + part.text,
      globPrefix: acc.globPrefix ?? (part.globPrefix === null ? null : acc.text + part.globPrefix),
      reading: worst(acc.reading, part.reading),
    }),
    { text: "", globPrefix: null, reading: "literal" },
  );

// The parser reads the script as bash, so a comment and a line continuation are not words, and a command
// inside `$(...)`, `<(...)`, a function, or a compound command is a simple command of its own. The data words
// are reached by the walk after their statement, so the statement marks them by offset (the walk hands out a
// fresh object per visit) and the word visit sorts them out.
function parseCommands(task: Task): Commands {
  if (task.script == null) {
    const words = [task.command, ...(task.args ?? [])].map(asWord);
    return { commands: [{ words: unalias(words), assigns: [] }], words, data: [] };
  }
  const commands: Command[] = [];
  const words: Word[] = [];
  const data: Word[] = [];
  const isData = new Set<number>();
  syntax.Walk(parser.Parse(task.script, ""), (node) => {
    if (node === null) return true;
    switch (syntax.NodeType(node)) {
      case "Stmt":
        if ((node as Sh.Stmt).Negated) commands.push({ words: [asWord("!")], assigns: [] });
        for (const redirect of present((node as Sh.Stmt).Redirs)) {
          for (const data of [redirect.Hdoc, namesFile(redirect) ? null : redirect.Word]) {
            if (data !== null) isData.add(data.Pos().Offset());
          }
        }
        break;
      case "CallExpr": {
        const { Args, Assigns } = node as Sh.CallExpr;
        commands.push({
          words: unalias(present(Args).map((arg) => wordOf(arg))),
          assigns: present(Assigns).flatMap((a) => (a.Name === null ? [] : [a.Name.Value])),
        });
        break;
      }
      case "DeclClause":
        commands.push({
          words: [asWord((node as Sh.DeclClause).Variant?.Value ?? "")],
          assigns: [],
        });
        break;
      case "Word": {
        const quoted = isData.has(node.Pos().Offset());
        (quoted ? data : words).push(wordOf(node as Sh.Word, quoted));
        break;
      }
      default: {
        const keyword = keywordOf(node);
        if (keyword !== undefined) commands.push({ words: [asWord(keyword)], assigns: [] });
      }
    }
    return true;
  });
  return { commands, words, data };
}

// A compound command is a command named by its keyword, so the gate's rule, which allows only simple commands
// of bun, cargo, set, and noop, refuses a loop or a test there by name; the commands inside it are audited too.
const KEYWORDS: Record<string, string> = {
  ArithmCmd: "((",
  CaseClause: "case",
  CoprocClause: "coproc",
  ForClause: "for",
  FuncDecl: "function",
  IfClause: "if",
  LetClause: "let",
  TestClause: "[[",
  TimeClause: "time",
};
const keywordOf = (node: Sh.Node): string | undefined =>
  syntax.NodeType(node) === "WhileClause"
    ? (node as Sh.WhileClause).Until
      ? "until"
      : "while"
    : KEYWORDS[syntax.NodeType(node)];

const isParseError = (error: unknown): error is ParseError =>
  typeof error === "object" &&
  error !== null &&
  "Text" in error &&
  typeof (error as ParseError).Error === "function";

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
const underBuild = (globPrefix: string): boolean => under(BUILD_DIR, posix.normalize(globPrefix));
// Every key of a moon glob list is a glob, a key with no pattern character included.
const buildGlobs = (globs: Record<string, unknown> | null | undefined): string[] =>
  Object.keys(globs ?? {}).filter((glob) => underBuild(asWord(glob).globPrefix ?? glob));

// A declared input is workspace-relative in the resolved graph, so it counts for every task. A command word is
// relative to the task's cwd, so it counts only when that is the workspace root, and only as a relative path:
// `/build/x` is a filesystem path, and a word with no slash (`build` alone) is a task or script name. What a
// script opens is not in the graph, so a read the task does not declare stays invisible here.
const namedBuildPaths = (project: string, task: Task, { words }: Commands): string[] => {
  const atRoot = project === ROOT_PROJECT || task.options?.runFromWorkspaceRoot === true;
  const named = atRoot
    ? words
        .filter((w) => w.globPrefix === null)
        .map((w) => w.text)
        .filter((text) => text.includes("/"))
    : [];
  const inputs = Object.keys(task.inputFiles ?? {});
  return [...new Set([...named, ...inputs].map(normalized))].filter((path) =>
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
  // A script the parser refuses is a finding against its task, and that task has no commands to judge.
  const commandsOf = new Map<string, Commands>();
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      try {
        commandsOf.set(target, parseCommands(task));
      } catch (error) {
        if (!isParseError(error)) throw error;
        findings.push(`${target}: unparsable script (${error.Error()})`);
        commandsOf.set(target, { commands: [], words: [], data: [] });
      }
    }
  }
  for (const [project, tasks] of Object.entries(graph)) {
    for (const [id, task] of Object.entries(tasks)) {
      const target = `${project}:${id}`;
      const parsed = commandsOf.get(target) ?? { commands: [], words: [], data: [] };
      const { commands, words } = parsed;
      if (commands.some(({ words }) => runsBunx(words))) {
        findings.push(`${target}: runs bunx (bun's global cache stands in for a missing package)`);
      }
      for (const w of [...words, ...parsed.data].filter((w) => w.reading === "opaque")) {
        findings.push(
          `${target}: the word ${w.text} holds an extglob pattern the parser keeps as text, so a command inside it is unread`,
        );
      }
      const atRoot = project === ROOT_PROJECT || task.options?.runFromWorkspaceRoot === true;
      for (const w of atRoot ? words : []) {
        if (w.globPrefix !== null && underBuild(w.globPrefix)) {
          findings.push(
            `${target}: names the glob ${w.text}; a reader under build/ declares the file or directory it reads`,
          );
        }
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
      for (const path of namedBuildPaths(project, task, parsed)) {
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
    const parsed = commandsOf.get(target) ?? { commands: [], words: [], data: [] };
    for (const w of [...parsed.words, ...parsed.data].filter((w) => w.reading !== "literal")) {
      findings.push(
        `${target}: the word ${w.text} inside ${GATE} is not literal (the rules judge only what they can read)`,
      );
    }
    for (const { words, assigns } of parsed.commands) {
      for (const name of assigns) {
        findings.push(
          `${target}: ${name} is assigned inside ${GATE} (the rules read the task's env, not its script's)`,
        );
      }
      const [word, ...rest] = words.map((w) => w.text);
      if (word === undefined) continue;
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
