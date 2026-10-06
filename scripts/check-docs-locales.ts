#!/usr/bin/env bun
// Translated docs live in directories mirroring the English tree, which the docs site turns into
// locales with a language switcher. A page in one language and not another is a dead switcher
// entry, so a present locale is judged file-for-file against docs/, and each mirrored page keeps the
// English page's generated regions byte for byte and its structure (headings, fences, table rows,
// inline code), since those carry identifiers a translation must not drift from.

import { readFileSync, statSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { parseArgs } from "node:util";

export const LOCALES = ["zh-cn", "zh-tw"] as const;
export type Locale = (typeof LOCALES)[number];

export type LocaleReport =
  | { readonly locale: Locale; readonly present: false }
  | {
      readonly locale: Locale;
      readonly present: true;
      /** English pages with no mirror under docs/<locale>/. */
      readonly missing: readonly string[];
      /** Pages under docs/<locale>/ that mirror no English page. */
      readonly extra: readonly string[];
      /** Mirrored pages whose generated region (`<!-- BEGIN GENERATED: name -->`) differs from the English one, each `<page>: generated region <name>` under its root-relative path. */
      readonly generatedDrift: readonly string[];
      /** Mirrored pages whose structure (headings, fences, table rows, inline code) differs from the English one, each `<page>: <measure or span>` under its root-relative path. */
      readonly structureDrift: readonly string[];
      readonly readmeMissing: boolean;
    };

const toPosix = (path: string): string => path.split(sep).join("/");

/** The locale a root-relative posix page label is a translation for: under docs/<locale>/, or the root README.<locale>.md. */
export function localeOf(page: string): Locale | undefined {
  return LOCALES.find(
    (locale) => page.startsWith(`docs/${locale}/`) || page === `README.${locale}.md`,
  );
}

const isDirectory = (path: string): boolean =>
  statSync(path, { throwIfNoEntry: false })?.isDirectory() ?? false;
const isFile = (path: string): boolean =>
  statSync(path, { throwIfNoEntry: false })?.isFile() ?? false;

// A generated region is rendered into the English page by a script that knows nothing of the locale
// copies, so a translated page carries it byte for byte or it is stale: the renderer's own check reads
// docs/architecture.md alone.
const GENERATED =
  /<!-- BEGIN GENERATED: (\S+?)(?: \([^)]*\))? -->\n[\s\S]*?<!-- END GENERATED: \1 -->/g;

function generatedRegions(file: string): Map<string, string> {
  const regions = new Map<string, string>();
  for (const match of readFileSync(file, "utf8").matchAll(GENERATED))
    regions.set(match[1] ?? "", match[0]);
  return regions;
}

// A translation keeps the English page's shape: the same headings, fences, and table rows, and the same
// inline code spans, which are identifiers and never translated. A count or a span that differs is a page
// that drifted from its English, a missing row or a renamed flag, which no reader of one language sees.
// Bun's Markdown renderer reads the page, so the constructs' edge cases (a span holding backticks or
// wrapping a line, a fence inside a list item, a quoted heading) are the parser's, not this check's.
interface Structure {
  readonly headings: number;
  readonly fences: number;
  /** Header and body rows; the delimiter row is syntax, not a row. */
  readonly tableRows: number;
  /** Every inline code span, in order of appearance, its line breaks read as spaces; its other whitespace is content. */
  readonly inlineCode: readonly string[];
}

function structureOf(file: string): Structure {
  let headings = 0;
  let fences = 0;
  let tableRows = 0;
  const inlineCode: string[] = [];
  Bun.markdown.render(readFileSync(file, "utf8"), {
    heading: () => {
      headings++;
      return "";
    },
    code: () => {
      fences++;
      return "";
    },
    tr: () => {
      tableRows++;
      return "";
    },
    codespan: (content) => {
      inlineCode.push(content.replace(/\n/g, " ").trim());
      return "";
    },
  });
  return { headings, fences, tableRows, inlineCode };
}

function inlineCodeDiff(ours: readonly string[], theirs: readonly string[]): string[] {
  const counts = new Map<string, number>();
  for (const span of ours) counts.set(span, (counts.get(span) ?? 0) + 1);
  for (const span of theirs) counts.set(span, (counts.get(span) ?? 0) - 1);
  return [...counts]
    .filter(([, count]) => count !== 0)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(
      ([span, count]) =>
        `${count > 0 ? "English only" : "translation only"} \`${span}\`${Math.abs(count) > 1 ? ` x${Math.abs(count)}` : ""}`,
    );
}

function structureDriftOf(english: string, translation: string): string[] {
  const ours = structureOf(english);
  const theirs = structureOf(translation);
  const counts = (["headings", "fences", "tableRows"] as const)
    .filter((measure) => ours[measure] !== theirs[measure])
    .map((measure) => `${measure} ${theirs[measure]} vs ${ours[measure]} in the English`);
  return [...counts, ...inlineCodeDiff(ours.inlineCode, theirs.inlineCode)];
}

function pages(dir: string): string[] {
  if (!isDirectory(dir)) return [];
  return [...new Bun.Glob("**/*.md").scanSync({ cwd: dir, onlyFiles: true })].map(toPosix).sort();
}

export function checkLocales(root: string): LocaleReport[] {
  const docs = join(root, "docs");
  // The English tree is the reference, so its absence is a wrong root, never a tree with nothing to mirror.
  if (!isDirectory(docs)) {
    throw new Error(`${docs} is not a directory; the English docs tree is the reference`);
  }
  const english = pages(docs).filter((page) => localeOf(`docs/${page}`) === undefined);
  // A reference with no page would make any locale a mirror of nothing.
  if (english.length === 0) {
    throw new Error(`${docs} holds no .md page; the English docs tree is the reference`);
  }
  return LOCALES.map((locale) => {
    const dir = join(docs, locale);
    const readme = join(root, `README.${locale}.md`);
    if (!isDirectory(dir) && !isFile(readme)) return { locale, present: false };
    const mirrored = new Set(pages(dir));
    const wanted = new Set(english);
    const generatedDrift = english
      .filter((page) => mirrored.has(page))
      .flatMap((page) => {
        const ours = generatedRegions(join(docs, page));
        const theirs = generatedRegions(join(dir, page));
        // Both directions: a region the English page lost but the translation kept is drift too.
        const names = new Set([...ours.keys(), ...theirs.keys()]);
        return [...names]
          .filter((name) => ours.get(name) !== theirs.get(name))
          .sort()
          .map((name) => `docs/${locale}/${page}: generated region ${name}`);
      });
    const readmeMissing = !isFile(readme);
    const structureDrift = [
      ...english
        .filter((page) => mirrored.has(page))
        .map((page) => [`docs/${locale}/${page}`, join(docs, page), join(dir, page)] as const),
      ...(readmeMissing ? [] : [[`README.${locale}.md`, join(root, "README.md"), readme] as const]),
    ].flatMap(([label, ours, theirs]) =>
      structureDriftOf(ours, theirs).map((detail) => `${label}: ${detail}`),
    );
    return {
      locale,
      present: true,
      missing: english.filter((page) => !mirrored.has(page)),
      extra: [...mirrored].filter((page) => !wanted.has(page)),
      generatedDrift,
      structureDrift,
      readmeMissing,
    };
  });
}

export function problemsOf(reports: readonly LocaleReport[]): string[] {
  return reports.flatMap((report) => {
    if (!report.present) return [];
    const { locale } = report;
    return [
      ...(report.readmeMissing ? [`README.${locale}.md is missing (docs/${locale}/ exists)`] : []),
      ...report.missing.map(
        (page) => `docs/${locale}/${page} is missing (docs/${page} has no mirror)`,
      ),
      ...report.extra.map((page) => `docs/${locale}/${page} mirrors nothing under docs/`),
      ...report.generatedDrift.map(
        (entry) => `${entry} differs from the English page's; copy it byte for byte`,
      ),
      ...report.structureDrift.map(
        (entry) =>
          `${entry}; a translation keeps the English page's headings, fences, table rows, and inline code`,
      ),
    ];
  });
}

const USAGE = [
  "usage: check-docs-locales.ts [--root <dir>]",
  "  --root  the repository root (default: cwd)",
  "exit 0: every present locale mirrors docs/ file-for-file, its generated regions byte-identical and its structure" +
    " (headings, fences, table rows, inline code) equal to the English (or no locale exists yet);" +
    " 1: problems, each printed; 2: usage or no docs/ under the root",
].join("\n");

function parseCli(argv: readonly string[]): { root: string } {
  try {
    const { values } = parseArgs({
      args: [...argv],
      options: { root: { type: "string" } },
      strict: true,
    });
    return { root: resolve(values.root ?? process.cwd()) };
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
  }
}

if (import.meta.main) {
  let reports: LocaleReport[];
  try {
    reports = checkLocales(parseCli(process.argv.slice(2)).root);
  } catch (error) {
    console.error(`check-docs-locales: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(2);
  }
  const problems = problemsOf(reports);
  if (problems.length > 0) {
    console.error(`check-docs-locales: ${problems.length} problem(s)\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  const present = reports.filter((report) => report.present).map((report) => report.locale);
  console.log(
    present.length === 0
      ? `check-docs-locales: no locale tree yet (${LOCALES.join(", ")} absent)`
      : `check-docs-locales: ${present.join(", ")} mirror docs/ file-for-file`,
  );
}
