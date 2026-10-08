#!/usr/bin/env bun
// The page probe behind `moon run check-docs-probe`. Bun's Markdown renderer decides the block structure, so
// prose is what renders as a paragraph or a list item (a loose item's paragraphs count as the item); front
// matter is blanked line for line so line numbers match the file.
//
//   BEGIN/END GENERATED region     -> dropped where the renderer sees HTML blocks; a marker quoted in a fence is code
//   path                           -> a backticked token with a slash and an extension (or ./, ../, a trailing slash),
//                                     or a relative link destination
//   <placeholder>, glob, owner/repo -> left alone, like a bare file name: a page may name files the reader will create
//   translated page                -> paths and links only (check-docs-locales says which): a whitespace word count
//                                     does not read CJK, so the English page carries the cap and the mirror check
//                                     keeps the trees file-for-file

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { localeOf } from "./check-docs-locales";
import { gitEnv } from "./lib";
import { toPosix } from "./lib.ts";
import { linkFile, readPage } from "./markdown-page";
import { realpath, withinRoot } from "./repo-paths";

export const DEFAULT_MAX_WORDS = 70;

export interface Finding {
  readonly file: string;
  /** One-based line where the unit or token starts. */
  readonly line: number;
  readonly message: string;
  /** `page hash`: the baseline allowance this finding would match (see readBaseline). */
  readonly key: string;
  /** What the hash covers, for the baseline's comment column. */
  readonly subject: string;
  readonly kind: "paragraph" | "list item" | "path" | "link";
}

/** Prose is whitespace-normalized before hashing; a path is hashed as written. */
function fingerprint(kind: Finding["kind"], subject: string): string {
  const prose = kind === "paragraph" || kind === "list item";
  const normalized = prose ? subject.replace(/\s+/g, " ").trim() : subject;
  return createHash("sha256").update(`${kind}\n${normalized}`).digest("hex").slice(0, 8);
}

function finding(
  file: string,
  line: number,
  kind: Finding["kind"],
  subject: string,
  message: string,
): Finding {
  return { file, line, message, kind, subject, key: `${file} ${fingerprint(kind, subject)}` };
}

export interface ProbeOptions {
  readonly root: string;
  readonly maxWords: number;
  /** false: word counts only, for pages that describe another repository's files. */
  readonly paths: boolean;
  /** Extra directories a slash path also resolves against: a shipped tree that mirrors the layout the page describes. */
  readonly bases?: readonly string[];
}

export interface Unit {
  readonly kind: "paragraph" | "item";
  readonly line: number;
  /** The prose as the reader sees it: link labels and code spans kept, markup gone. */
  readonly text: string;
}

export interface Scan {
  readonly units: Unit[];
  readonly codespans: { readonly text: string; readonly line: number }[];
  readonly links: { readonly href: string; readonly line: number }[];
}

// Marker bytes the renderer callbacks emit; blocks nest, inlines do not. P and L are prose
// (paragraph, list item); N is a block whose paths and links are checked but whose words are not counted.
const OPEN = "\u0001";
const INLINE_END = "\u0002";
const BLOCK_END = "\u0003";
const isBlockKind = (ch: string | undefined) => ch === "P" || ch === "L" || ch === "N";

function blankFrontMatter(text: string): string[] {
  const lines = text.split("\n").map((line) => line.replace(/\r$/, ""));
  const out = [...lines];
  // Only a closed block is front matter; a lone --- is a thematic break and the page is prose.
  if (lines[0] === "---") {
    const close = lines.indexOf("---", 1);
    if (close !== -1) for (let i = 0; i <= close; i++) out[i] = "";
  }
  return out;
}

const ENTITIES: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
};
const unescapeEntities = (s: string) =>
  s.replace(/&(?:amp|lt|gt|quot|#39);/g, (m) => ENTITIES[m] ?? m);

function ownText(s: string): string {
  let out = "";
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i] as string;
    if (ch === OPEN && isBlockKind(s[i + 1])) depth++;
    else if (ch === BLOCK_END) depth--;
    else if (depth === 0) out += ch;
  }
  return out;
}

function nestedBlocks(s: string): string[] {
  const blocks: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === OPEN && isBlockKind(s[i + 1])) {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === BLOCK_END) {
      depth--;
      if (depth === 0 && start !== -1) {
        blocks.push(s.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return blocks;
}

/** Cuts each BEGIN region through the END marker of the same name; a BEGIN with no matching END, or a stray END, hides nothing. */
function dropGeneratedRegions(stream: string): string {
  let out = stream;
  const begin = new RegExp(`${OPEN}G([^${BLOCK_END}]*)${BLOCK_END}`);
  for (let m = begin.exec(out); m; m = begin.exec(out)) {
    const close = `${OPEN}g${m[1]}${BLOCK_END}`;
    const at = out.indexOf(close, m.index + m[0].length);
    out =
      at === -1
        ? out.slice(0, m.index) + out.slice(m.index + m[0].length)
        : out.slice(0, m.index) + out.slice(at + close.length);
  }
  return out.replace(new RegExp(`${OPEN}g[^${BLOCK_END}]*${BLOCK_END}`, "g"), "");
}

const ONE_LINE_COMMENT = /^ {0,3}<!--.*-->\s*$/;
const LINK_MARK = new RegExp(`${OPEN}A[^${INLINE_END}]*${INLINE_END}`, "g");
const CODESPAN_MARK = new RegExp(`${OPEN}C([^${INLINE_END}]*)${INLINE_END}`, "g");
const HTML_MARK = new RegExp(`${OPEN}H([^${INLINE_END}]*)${INLINE_END}`, "g");
const INLINE_COMMENT = /^<!--[\s\S]*-->$/;
// The chunk is a whole tag by provenance, so the name alone decides; attributes may hold any character.
const BREAK_TAG = /^<br(?![\w-])/i;
const INLINE_TAG = /^<\/?[a-zA-Z][\s\S]*>$/;

/**
 * Bun's text callback receives raw HTML as a chunk of its own (inline, block, and inside code spans
 * alike), while escaped text (`&lt;!--`, `\<!--`) arrives split at the `<`. The chunk is the
 * provenance a regex over the joined text would lose, so the text callback marks it and each owner
 * decides what the mark means:
 *   html callback      -> unwraps the marks and reads the GENERATED region markers
 *   codespan callback  -> unwraps the marks; code is literal
 *   paragraph (here)   -> a whole comment is nothing, a <br> a space, any other whole tag nothing
 */
function inlineHtml(chunk: string): string {
  if (INLINE_COMMENT.test(chunk)) return "";
  if (BREAK_TAG.test(chunk)) return " ";
  if (INLINE_TAG.test(chunk)) return "";
  return chunk;
}

export function scanPage(text: string): Scan {
  const lines = blankFrontMatter(text);
  const nothing = () => "";
  const same = (c: string) => c;
  const stream = Bun.markdown.render(lines.join("\n"), {
    text: (c: string) => (c.startsWith("<") ? `${OPEN}H${c}${INLINE_END}` : c),
    strong: same,
    emphasis: same,
    strikethrough: same,
    blockquote: same,
    list: same,
    heading: (c: string) => `${OPEN}N${c}${BLOCK_END}`,
    code: nothing,
    table: (c: string) => `${OPEN}N${c}${BLOCK_END}`,
    html: (c: string) => {
      // Only the documented marker comment, with its name, opens or closes a region.
      const raw = c.replace(HTML_MARK, "$1");
      const begin = /^\s*<!-- BEGIN GENERATED: (\S+)/.exec(raw);
      const end = /^\s*<!-- END GENERATED: (\S+)/.exec(raw);
      if (begin) return `${OPEN}G${begin[1]}${BLOCK_END}`;
      if (end) return `${OPEN}g${end[1]}${BLOCK_END}`;
      return "";
    },
    hr: nothing,
    image: nothing,
    codespan: (c: string) => `${OPEN}C${c.replace(HTML_MARK, "$1")}${INLINE_END}`,
    link: (c: string, attrs: { href?: string }) => `${OPEN}A${attrs.href ?? ""}${INLINE_END}${c}`,
    paragraph: (c: string) => `${OPEN}P${c}${BLOCK_END}`,
    listItem: (c: string) => `${OPEN}L${c}${BLOCK_END}`,
  });

  const prose = dropGeneratedRegions(stream);

  const scan: Scan = { units: [], codespans: [], links: [] };
  let cursor = 0;
  // Rendered text has lost its markup (**bold**, [label](url) with the url between label and text),
  // so a line matches when it carries the unit's first two words, letters and digits only. Fenced,
  // indented, and comment lines are skipped: a path quoted in one before the prose that names it
  // would otherwise claim the finding's line.
  const searchable = readPage(lines.join("\n")).text.map((line) =>
    line === undefined || ONE_LINE_COMMENT.test(line) ? "" : line,
  );
  const letters = (text: string) => text.replace(/[^A-Za-z0-9]+/g, "");
  const locate = (needle: string): number => {
    const probes = unescapeEntities(needle).split(/\s+/).map(letters).filter(Boolean).slice(0, 2);
    if (probes.length === 0) return cursor;
    for (let i = cursor; i < searchable.length; i++) {
      const line = letters(searchable[i] ?? "");
      if (probes.every((probe) => line.includes(probe))) return i;
    }
    return cursor;
  };
  const reads = (markers: string): string =>
    markers
      .replace(LINK_MARK, "")
      .replace(CODESPAN_MARK, "$1")
      .replace(HTML_MARK, (_mark, raw: string) => inlineHtml(raw));
  // `folded` marks a paragraph that is a list item's direct child: a loose item renders its text as
  // paragraph blocks and nothing of its own, so the item counts them and the paragraph pushes no unit
  // of its own. Each block is still visited in source order, so the line cursor moves as the page reads.
  const visit = (block: string, folded = false) => {
    const prose = block[1] !== "N";
    const kind = block[1] === "L" ? "item" : "paragraph";
    const inner = block.slice(2, -1);
    const own = ownText(inner);
    const plain = reads(own);
    const nested = nestedBlocks(inner);
    const parts =
      kind === "item"
        ? [plain, ...nested.filter((b) => b[1] === "P").map((b) => reads(ownText(b.slice(2, -1))))]
        : [plain];
    const unitText = parts.join(" ").trim();
    // Located by the first paragraph alone: a needle spanning two paragraphs matches no source line.
    const lead = parts.find((part) => part.trim() !== "") ?? "";
    const firstLine = lead.split("\n").find((l) => l.trim() !== "") ?? "";
    const line = locate(firstLine);
    if (prose && !folded && unitText !== "") {
      scan.units.push({ kind, line: line + 1, text: unescapeEntities(unitText) });
    }
    for (const m of own.matchAll(CODESPAN_MARK)) {
      const code = unescapeEntities(m[1] ?? "");
      scan.codespans.push({ text: code, line: locate(`\`${code}\``) + 1 });
    }
    for (const m of own.matchAll(new RegExp(`${OPEN}A([^${INLINE_END}]*)${INLINE_END}`, "g"))) {
      const href = unescapeEntities(m[1] ?? "");
      scan.links.push({ href, line: locate(href) + 1 });
    }
    // The next unit starts after this one, so a repeated opening line finds its own line, not this one again.
    if (plain.trim() !== "") cursor = line + plain.trim().split("\n").length;
    for (const child of nested) visit(child, kind === "item" && child[1] === "P");
  };
  for (const block of nestedBlocks(prose)) visit(block);
  return scan;
}

export function wordCount(text: string): number {
  return text.split(/\s+/).filter(Boolean).length;
}

const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const EXTENSION = /\.[a-z0-9]{1,10}$/i;

export function pathCandidate(token: string): string | null {
  const path = token
    .trim()
    .replace(/[.,;:]+$/, "")
    .replace(/:\d+(?:-\d+)?$/, "")
    .replace(/[.,;:]+$/, "");
  if (path === "" || /[<>*?${}|\s~[\]]/.test(path) || SCHEME.test(path) || /^[-/]/.test(path))
    return null;
  if (path.startsWith("./") || path.startsWith("../") || path.endsWith("/")) {
    const bare = path.replace(/\/$/, "");
    return bare === "" || bare === "." || bare === ".." ? null : path;
  }
  return path.includes("/") && EXTENSION.test(path) ? path : null;
}

/**
 * The page's directory, every directory up to the root, then the extra bases: a page under
 * docs/security/ may name `docs/cli.md` or `cli.md`.
 */
function bases(root: string, pageDir: string, extra: readonly string[]): string[] {
  const out = [pageDir];
  for (let dir = pageDir; dir !== root && dir.startsWith(root); dir = dirname(dir))
    out.push(dirname(dir));
  return [...out, ...extra];
}

/** A file a slash path may name at one base; `query` is how git is asked about it, directory marker kept. */
interface Candidate {
  readonly file: string;
  readonly query: string;
}

/** The root itself is `.`: an empty relative path plus the marker would be `/`, which git refuses, and one refusal would silence the whole page. */
function gitQuery(root: string, file: string, directory: boolean): string {
  const rel = toPosix(relative(root, file));
  return `${rel === "" ? "." : rel}${directory ? "/" : ""}`;
}

function candidates(root: string, pageDir: string, extra: readonly string[], path: string) {
  const dirs =
    path.startsWith("./") || path.startsWith("../") ? [pageDir] : bases(root, pageDir, extra);
  const files: Candidate[] = dirs.map((base) => {
    const file = resolve(base, path);
    return { file, query: gitQuery(root, file, path.endsWith("/")) };
  });
  return { dirs, files };
}

/**
 * The files under `root` that git ignores, among the candidates, whether or not they exist: a built
 * icon or a tool cache exists on a machine that built it and not on a fresh clone, so an existence
 * check alone would change its verdict between the two. Git is asked with the directory marker kept,
 * since a `build/` rule matches `build/` and not `build`. The hook's GIT_* variables are scrubbed so
 * the query reads this root, and outside a git repository nothing is ignored.
 */
function ignoredBy(root: string, files: readonly Candidate[]): Set<string> {
  const inside = files.filter(({ file }) => withinRoot(root, file));
  const queries = [...new Set(inside.map(({ query }) => query))];
  if (queries.length === 0) return new Set();
  const run = Bun.spawnSync(["git", "-C", root, "check-ignore", "-z", "--stdin"], {
    stdin: new TextEncoder().encode(`${queries.join("\0")}\0`),
    env: gitEnv(),
    stdout: "pipe",
    stderr: "pipe",
  });
  // Exit 1 is "none ignored"; outside a repository nothing is ignored; any other failure (a path
  // beyond a symlink, an unreadable index) must fail the probe, never pass the page as unignored.
  if (run.exitCode === 1) return new Set();
  if (run.exitCode !== 0) {
    const stderr = run.stderr.toString().trim();
    if (/^fatal: not a git repository\b/.test(stderr)) return new Set();
    throw new Error(`git check-ignore failed in ${root}: ${stderr}`);
  }
  const ignoredQueries = new Set(run.stdout.toString().split("\0").filter(Boolean));
  return new Set(inside.filter(({ query }) => ignoredQueries.has(query)).map(({ file }) => file));
}

/**
 * A slash path is checked only when its first segment exists at one of the bases:
 * `agents/openai.yaml` in a page about some other layout names nothing here and is left alone,
 * while `docs/gone.md` under a real `docs/` is the stale pointer the probe exists for.
 */
function verdict(
  root: string,
  pageDir: string,
  extra: readonly string[],
  path: string,
  ignored: ReadonlySet<string>,
): "ok" | "missing" | "ignored" | "foreign" | "outside" {
  const { dirs, files } = candidates(root, pageDir, extra, path);
  const hits = files.map(({ file }) => file).filter((file) => existsSync(file));
  if (hits.some((file) => withinRoot(root, file) && !ignored.has(file))) return "ok";
  if (files.some(({ file }) => ignored.has(file))) return "ignored";
  if (hits.length > 0) return "outside";
  const first = path.split("/")[0] ?? "";
  const anchored =
    first === "." || first === ".." || dirs.some((base) => existsSync(resolve(base, first)));
  return anchored ? "missing" : "foreign";
}

const NOT_IN_REPOSITORY = "is not part of the repository (git ignores it)";

export function probePage(text: string, file: string, options: ProbeOptions): Finding[] {
  const findings: Finding[] = [];
  const pageDir = dirname(resolve(options.root, file));
  const scan = scanPage(text);
  const capped = localeOf(file) === undefined ? scan.units : [];
  for (const unit of capped) {
    const words = wordCount(unit.text);
    if (words > options.maxWords) {
      const noun = unit.kind === "item" ? "list item" : "paragraph";
      findings.push(
        finding(
          file,
          unit.line,
          noun,
          unit.text,
          `${noun} of ${words} words; the cap is ${options.maxWords}. Split it, or turn its facts into bullets, a table, or numbered steps`,
        ),
      );
    }
  }
  if (!options.paths) return findings;
  const extra = options.bases ?? [];
  const paths = scan.codespans.map(({ text: code, line }) => ({ path: pathCandidate(code), line }));
  const links = scan.links
    .map(({ href, line }) => ({ target: linkFile(href), line }))
    .filter(({ target }) => target !== "" && !SCHEME.test(target) && !isAbsolute(target))
    .map(({ target, line }) => ({ target, line, resolved: resolve(pageDir, target) }));
  const ignored = ignoredBy(options.root, [
    ...paths.flatMap(({ path }) =>
      path === null ? [] : candidates(options.root, pageDir, extra, path).files,
    ),
    ...links.map(({ target, resolved }) => ({
      file: resolved,
      query: gitQuery(options.root, resolved, target.endsWith("/")),
    })),
  ]);
  for (const { path, line } of paths) {
    if (path === null) continue;
    const state = verdict(options.root, pageDir, extra, path, ignored);
    if (state === "missing")
      findings.push(finding(file, line, "path", path, `\`${path}\` does not exist`));
    if (state === "ignored")
      findings.push(finding(file, line, "path", path, `\`${path}\` ${NOT_IN_REPOSITORY}`));
    if (state === "outside")
      findings.push(finding(file, line, "path", path, `\`${path}\` escapes the repository`));
  }
  for (const { target, line, resolved } of links) {
    if (!withinRoot(options.root, resolved)) {
      findings.push(
        finding(file, line, "link", target, `link target ${target} escapes the repository`),
      );
    } else if (ignored.has(resolved)) {
      findings.push(
        finding(file, line, "link", target, `link target ${target} ${NOT_IN_REPOSITORY}`),
      );
    } else if (!existsSync(resolved)) {
      findings.push(finding(file, line, "link", target, `link target ${target} does not exist`));
    }
  }
  return findings.sort((a, b) => a.line - b.line);
}

// An allowance names the page and a fingerprint of the unit's own text (or the path a path finding
// names), never a line: an unrelated line shift leaves it valid, and it goes stale exactly when its
// paragraph changed or vanished. `page hash  # kind: first words`; the comment is for the reader.
const BASELINE_ENTRY = /^(\S+) ([0-9a-f]{8})(?:\s+#.*)?$/;

export function readBaseline(text: string, label: string): Set<string> {
  const keys = new Set<string>();
  text.split("\n").forEach((raw, index) => {
    const line = raw.replace(/\r$/, "").trim();
    if (line === "" || line.startsWith("#")) return;
    const entry = BASELINE_ENTRY.exec(line);
    if (!entry) {
      throw new Error(
        `${label}:${index + 1}: a baseline entry is "page hash" with an optional # comment, got "${line}"`,
      );
    }
    keys.add(`${entry[1]} ${entry[2]}`);
  });
  return keys;
}

export function baselineLines(findings: readonly Finding[]): string[] {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const f of findings) {
    if (seen.has(f.key)) continue;
    seen.add(f.key);
    const words = f.subject.replace(/\s+/g, " ").trim().split(" ").slice(0, 6).join(" ");
    lines.push(`${f.key}  # ${f.kind}: ${words}`);
  }
  return lines;
}

export interface Judgment {
  readonly fresh: Finding[];
  readonly stale: string[];
  readonly allowed: number;
}

export function judge(findings: readonly Finding[], baseline: ReadonlySet<string>): Judgment {
  const fired = new Set<string>();
  const fresh: Finding[] = [];
  for (const finding of findings) {
    if (baseline.has(finding.key)) fired.add(finding.key);
    else fresh.push(finding);
  }
  const stale = [...baseline].filter((key) => !fired.has(key)).sort();
  return { fresh, stale, allowed: findings.length - fresh.length };
}

const USAGE = [
  // The file names itself, so a vendored copy under another name prints a command that exists there.
  `usage: ${basename(fileURLToPath(import.meta.url))} [--root <dir>] [--base <dir>]...` +
    " [--max-words <n>] [--shape-only] [--baseline <file>] <page.md | glob>...",
  "  --root        the repository root paths resolve against (default: cwd)",
  "  --base        a directory under the root that paths also resolve against (repeatable)",
  "  --max-words   the cap on a paragraph or list item (default: 70); a locale page is probed for paths and links only",
  "  --shape-only  word counts only; skip the check that named paths exist (refused with a locale page, which has no word count)",
  "  --baseline    a file of allowed findings (page and unit fingerprint); one that no longer fires fails too",
  "  --print-baseline  print the baseline lines for every finding of the pages, then exit 0",
  "  a page argument with a * is a glob, expanded under the root; one that matches nothing is an error",
  "exit 0: every page is clean; 1: findings, one per line as page:line: message; 2: usage or an unreadable page",
].join("\n");

interface CliOptions {
  readonly root: string;
  readonly bases: readonly string[];
  readonly maxWords: number;
  readonly paths: boolean;
  readonly baseline: string | undefined;
  readonly printBaseline: boolean;
  /** Root-relative, posix, sorted, globs expanded. */
  readonly pages: readonly string[];
}

function pageLabel(root: string, page: string): string {
  const absolute = realpath(resolve(root, page));
  if (!statSync(absolute, { throwIfNoEntry: false })?.isFile())
    throw new Error(`${page} is not a readable file`);
  return toPosix(relative(root, absolute)) || page;
}

/** Each page argument, globs expanded under the root. A pattern matching nothing is a renamed tree, so it fails rather than passing vacuously. */
export function expandPages(root: string, args: readonly string[]): string[] {
  const pages = new Set<string>();
  for (const arg of args) {
    if (!arg.includes("*")) {
      pages.add(pageLabel(root, arg));
      continue;
    }
    const matches = [...new Bun.Glob(arg).scanSync({ cwd: root, onlyFiles: true })];
    if (matches.length === 0) throw new Error(`${arg} matches no file under ${root}`);
    for (const match of matches) pages.add(pageLabel(root, match));
  }
  return [...pages].sort();
}

export function parseCli(argv: readonly string[]): CliOptions {
  const { values, positionals: pageArgs } = parseFlags(argv);
  const root = realpath(values.root ?? process.cwd());
  if (!statSync(root, { throwIfNoEntry: false })?.isDirectory())
    throw new Error(`--root ${root} is not a directory`);
  const maxWords =
    values["max-words"] === undefined ? DEFAULT_MAX_WORDS : Number(values["max-words"]);
  if (!Number.isInteger(maxWords) || maxWords < 1)
    throw new Error(`--max-words needs a positive integer\n${USAGE}`);
  if (pageArgs.length === 0) throw new Error(USAGE);
  const bases = (values.base ?? []).map((arg) => {
    const base = realpath(resolve(root, arg));
    if (!statSync(base, { throwIfNoEntry: false })?.isDirectory())
      throw new Error(`--base ${base} is not a directory`);
    if (!withinRoot(root, base)) throw new Error(`--base ${base} is outside the root ${root}`);
    return base;
  });
  const baseline = values.baseline === undefined ? undefined : resolve(root, values.baseline);
  if (baseline !== undefined && !statSync(baseline, { throwIfNoEntry: false })?.isFile())
    throw new Error(`--baseline ${baseline} is not a readable file`);
  const paths = values["shape-only"] !== true;
  const pages = expandPages(root, pageArgs);
  // A locale page skips the cap, so without the path check it would pass with nothing probed.
  const unchecked = paths ? [] : pages.filter((page) => localeOf(page) !== undefined);
  if (unchecked.length > 0) {
    throw new Error(
      `--shape-only leaves a locale page with nothing to check: ${unchecked.join(", ")}`,
    );
  }
  const printBaseline = values["print-baseline"] === true;
  return { root, bases, maxWords, paths, baseline, printBaseline, pages };
}

function parseFlags(argv: readonly string[]) {
  try {
    return parseArgs({
      args: [...argv],
      options: {
        root: { type: "string" },
        base: { type: "string", multiple: true },
        "max-words": { type: "string" },
        baseline: { type: "string" },
        "print-baseline": { type: "boolean" },
        "shape-only": { type: "boolean" },
      },
      strict: true,
      allowPositionals: true,
    });
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
  }
}

if (import.meta.main) {
  let options: CliOptions;
  let judgment: Judgment;
  let baselineLabel = "";
  try {
    options = parseCli(process.argv.slice(2));
    const findings: Finding[] = [];
    for (const page of options.pages) {
      findings.push(...probePage(readFileSync(resolve(options.root, page), "utf8"), page, options));
    }
    if (options.printBaseline) {
      for (const line of baselineLines(findings)) console.log(line);
      process.exit(0);
    }
    if (options.baseline === undefined) {
      judgment = { fresh: findings, stale: [], allowed: 0 };
    } else {
      baselineLabel = toPosix(relative(options.root, options.baseline));
      judgment = judge(
        findings,
        readBaseline(readFileSync(options.baseline, "utf8"), baselineLabel),
      );
    }
  } catch (error) {
    console.error(`docs-probe: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(2);
  }
  const { fresh, stale, allowed } = judgment;
  if (fresh.length === 0 && stale.length === 0) {
    const allowance = allowed > 0 ? `; ${allowed} finding(s) allowed by ${baselineLabel}` : "";
    const locale = options.pages.filter((page) => localeOf(page) !== undefined).length;
    const shapeOnly = locale > 0 ? `; ${locale} locale page(s) paths and links only` : "";
    console.log(
      `docs-probe: ${options.pages.length} page(s) clean (cap ${options.maxWords} words${shapeOnly})${allowance}`,
    );
    process.exit(0);
  }
  console.error(
    `docs-probe: ${fresh.length} finding(s) outside the baseline, ${stale.length} stale baseline line(s)`,
  );
  for (const finding of fresh)
    console.error(`  ${finding.file}:${finding.line}: ${finding.message}`);
  for (const key of stale)
    console.error(
      `  ${key}: no finding fires for this unit any more; remove the line from ${baselineLabel}`,
    );
  process.exit(1);
}
