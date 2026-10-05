#!/usr/bin/env bun
// Translated docs live in directories mirroring the English tree, which the docs site turns into
// locales with a language switcher. A page in one language and not another is a dead switcher
// entry, so a present locale is judged file-for-file against docs/:
//   locale absent (no docs/<locale>/, no README.<locale>.md)  -> nothing to judge, pass
//   locale present                                            -> README.<locale>.md exists, and the
//                                                                .md set under docs/<locale>/ equals
//                                                                the .md set under docs/ (locales excluded)

import { statSync } from "node:fs";
import { join, resolve, sep } from "node:path";

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
      readonly readmeMissing: boolean;
    };

const toPosix = (path: string): string => path.split(sep).join("/");

const isDirectory = (path: string): boolean =>
  statSync(path, { throwIfNoEntry: false })?.isDirectory() ?? false;
const isFile = (path: string): boolean =>
  statSync(path, { throwIfNoEntry: false })?.isFile() ?? false;

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
  const english = pages(docs).filter(
    (page) => !LOCALES.some((locale) => page.startsWith(`${locale}/`)),
  );
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
    return {
      locale,
      present: true,
      missing: english.filter((page) => !mirrored.has(page)),
      extra: [...mirrored].filter((page) => !wanted.has(page)),
      readmeMissing: !isFile(readme),
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
    ];
  });
}

const USAGE = [
  "usage: check-docs-locales.ts [--root <dir>]",
  "  --root  the repository root (default: cwd)",
  "exit 0: every present locale mirrors docs/ file-for-file (or no locale exists yet);" +
    " 1: problems, each printed; 2: usage or no docs/ under the root",
].join("\n");

function parseArgs(argv: readonly string[]): { root: string } {
  let root = process.cwd();
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--root") {
      const next = argv[++i];
      if (next === undefined) throw new Error(`--root needs a value\n${USAGE}`);
      root = resolve(next);
    } else throw new Error(`unknown argument: ${arg}\n${USAGE}`);
  }
  return { root };
}

if (import.meta.main) {
  let reports: LocaleReport[];
  try {
    reports = checkLocales(parseArgs(process.argv.slice(2)).root);
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
