#!/usr/bin/env bun

// CJK containment gate: a CJK character outside the files that are deliberately Chinese is an untranslated
// string on a canonical English surface (an inherited Chinese tool label once reached the options page).
// One `git grep -P` over the tracked tree does the scan; this wrapper owns the exclude list and the exit
// contract. PCRE2 reads \p{} and \x{} only in a UTF-8 locale and refuses the pattern outright under C, and
// the zh_CN bundle is grepped first so an engine that goes blind fails here instead of passing vacuously.

import { repoRoot } from "./lib.ts";

// Han, kana, hangul, bopomofo, plus the CJK-only blocks that ride along: punctuation, enclosed and
// compatibility letters, compatibility and fullwidth forms. tests/browser/ext_test.ts mirrors this class.
export const CJK_CLASS =
  "[\\p{Han}\\p{Hiragana}\\p{Katakana}\\p{Hangul}\\p{Bopomofo}\\x{3000}-\\x{303F}\\x{3200}-\\x{33FF}\\x{FE30}-\\x{FE4F}\\x{FF00}-\\x{FFEF}]";

/** The one file guaranteed to contain CJK: the engine control. */
export const CONTROL_FILE = "src/apps/extension/src/locales/zh_CN.yml";

/** Git pathspecs for the files allowed to carry CJK: the zh locale bundles, the language picker's native
 * names, the i18n fixtures, and translated docs (a `*` in a pathspec crosses `/`, so nested docs match). */
export const ALLOWED_PATHSPECS = [
  CONTROL_FILE,
  "src/apps/extension/src/locales/zh_TW.yml",
  "src/apps/extension/src/lib/native-language-names.ts",
  "src/apps/extension/tests/lib/i18n.test.ts",
  "docs/*.zh_CN.md",
  "docs/*.zh_TW.md",
  "README.zh_CN.md",
  "README.zh_TW.md",
];

export type CjkReport = { status: "clean" } | { status: "hits"; hits: string };

type Env = Record<string, string | undefined>;

function gitGrep(cwd: string, env: Env, args: string[]) {
  const run = Bun.spawnSync(["git", "grep", "-I", "-P", ...args], {
    cwd,
    env: { ...env, LC_ALL: "C.UTF-8" },
  });
  if (run.exitCode !== 0 && run.exitCode !== 1) {
    throw new Error(`git grep failed (exit ${run.exitCode}): ${run.stderr.toString().trim()}`);
  }
  return { matched: run.exitCode === 0, stdout: run.stdout.toString() };
}

export function checkCjk(cwd: string, env: Env = process.env): CjkReport {
  if (!gitGrep(cwd, env, ["-q", CJK_CLASS, "--", CONTROL_FILE]).matched) {
    throw new Error(
      `${CONTROL_FILE} matched no CJK: the regex engine is blind, not the tree clean`,
    );
  }
  const excludes = ALLOWED_PATHSPECS.map((p) => `:!${p}`);
  const scan = gitGrep(cwd, env, ["-n", CJK_CLASS, "--", ".", ...excludes]);
  return scan.matched ? { status: "hits", hits: scan.stdout.trimEnd() } : { status: "clean" };
}

if (import.meta.main) {
  const report = checkCjk(repoRoot);
  if (report.status === "hits") {
    console.error(report.hits);
    console.error(
      "\ncheck-cjk: CJK text outside the zh locale files; canonical strings are English, so move it " +
        "into src/apps/extension/src/locales/*.yml or a *.zh_CN.md / *.zh_TW.md translated doc",
    );
    process.exit(1);
  }
  console.log("check-cjk: no CJK outside the zh locale files and translated docs");
}
