#!/usr/bin/env bun

// A CJK character outside the deliberately Chinese files is an untranslated string on an English surface (an
// inherited Chinese tool label once reached the options page). One `git grep -P` scans the tracked tree.
//
//   PCRE2 under a non-UTF-8 ctype locale  -> refuses \p{} and \x{} outright, so grepEnv picks a UTF-8 locale first
//   zh_CN bundle grepped before the tree   -> an engine that goes blind fails here instead of passing vacuously

import { type Env, repoRoot } from "./lib.ts";

// Han, kana, hangul, bopomofo, plus the CJK-only blocks that ride along: punctuation, enclosed and
// compatibility letters, compatibility and fullwidth forms. tests/browser/ext_test.ts mirrors this class.
export const CJK_CLASS =
  "[\\p{Han}\\p{Hiragana}\\p{Katakana}\\p{Hangul}\\p{Bopomofo}\\x{3000}-\\x{303F}\\x{3200}-\\x{33FF}\\x{FE30}-\\x{FE4F}\\x{FF00}-\\x{FFEF}]";

/** The one file guaranteed to contain CJK: the engine control. */
export const CONTROL_FILE = "src/apps/extension/src/locales/zh_CN.yml";

/** Allowed to carry CJK. check-docs-locales holds the translated trees file-for-file to the English tree. */
export const ALLOWED_PATHSPECS = [
  CONTROL_FILE,
  "src/apps/extension/src/locales/zh_TW.yml",
  "src/apps/extension/src/lib/native-language-names.ts",
  "src/apps/extension/tests/lib/i18n.test.ts",
  "docs/zh-cn/",
  "docs/zh-tw/",
  "README.zh-cn.md",
  "README.zh-tw.md",
];

/** Tried in order when the inherited ctype locale is not UTF-8. C.UTF-8 is absent on macOS 14 and older,
 * where BSD libc falls back to C and `git grep -P` dies on the class, so a second candidate follows. */
export const LOCALE_CANDIDATES = ["C.UTF-8", "en_US.UTF-8"];

export type CjkReport = { status: "clean" } | { status: "hits"; hits: string };

function controlGrep(cwd: string, env: Env) {
  return Bun.spawnSync(["git", "grep", "-qIP", CJK_CLASS, "--", CONTROL_FILE], { cwd, env });
}

/** The environment the greps run with: `env` itself when its ctype locale (POSIX precedence: LC_ALL,
 * LC_CTYPE, LANG) is UTF-8, else the first candidate under which PCRE2 accepts the class. Exit 0 or 1
 * from the control grep means the pattern compiled; anything else is the engine refusing it. */
export function grepEnv(cwd: string, env: Env): Env {
  const ctype = env.LC_ALL || env.LC_CTYPE || env.LANG;
  if (ctype !== undefined && /(^|\.)utf-?8$/i.test(ctype)) return env;
  const refusals: string[] = [];
  for (const locale of LOCALE_CANDIDATES) {
    const candidate = { ...env, LC_ALL: locale };
    const probe = controlGrep(cwd, candidate);
    if (probe.exitCode === 0 || probe.exitCode === 1) return candidate;
    refusals.push(`${locale}: ${probe.stderr.toString().trim().split("\n")[0]}`);
  }
  throw new Error(
    `no UTF-8 locale accepts the CJK class in git grep -P; set LANG to a UTF-8 locale. ${refusals.join("; ")}`,
  );
}

export function checkCjk(cwd: string, env: Env = process.env): CjkReport {
  const resolved = grepEnv(cwd, env);
  const control = controlGrep(cwd, resolved);
  if (control.exitCode === 1) {
    throw new Error(
      `${CONTROL_FILE} matched no CJK: the regex engine is blind, not the tree clean`,
    );
  }
  if (control.exitCode !== 0) {
    throw new Error(
      `git grep failed (exit ${control.exitCode}): ${control.stderr.toString().trim()}`,
    );
  }
  const excludes = ALLOWED_PATHSPECS.map((p) => `:!${p}`);
  const scan = Bun.spawnSync(["git", "grep", "-nIP", CJK_CLASS, "--", ".", ...excludes], {
    cwd,
    env: resolved,
  });
  if (scan.exitCode !== 0 && scan.exitCode !== 1) {
    throw new Error(`git grep failed (exit ${scan.exitCode}): ${scan.stderr.toString().trim()}`);
  }
  return scan.exitCode === 0
    ? { status: "hits", hits: scan.stdout.toString().trimEnd() }
    : { status: "clean" };
}

if (import.meta.main) {
  const report = checkCjk(repoRoot);
  if (report.status === "hits") {
    console.error(report.hits);
    console.error(
      "\ncheck-cjk: CJK text outside the zh locale files; canonical strings are English, so move it " +
        "into src/apps/extension/src/locales/*.yml",
    );
    process.exit(1);
  }
  console.log("check-cjk: no CJK outside the zh locale files");
}
