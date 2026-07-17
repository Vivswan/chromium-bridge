#!/usr/bin/env bun

// CJK containment gate: Chinese/Japanese/Korean text may exist ONLY where it
// is deliberately Chinese - the zh locale bundles, translated docs, the
// native-name constants for the language picker, and the i18n test fixtures
// that exercise those bundles. Anywhere else, a CJK character means an
// untranslated string leaked into a canonical (English) surface - exactly the
// class of bug where an upstream-inherited Chinese tool label reached the
// options page - so this fails CI.
//
// Companion to the check-typography action (which handles look-alike
// punctuation); this one is about whole scripts, not characters that resemble
// ASCII.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

// Exact repo-relative paths allowed to contain CJK, and why.
const ALLOWED_FILES = new Set([
  // The Chinese locale bundles: the canonical home of every zh string.
  "src/apps/extension/src/locales/zh_CN.yml",
  "src/apps/extension/src/locales/zh_TW.yml",
  // The language picker's native names (each language naming itself),
  // rendered untranslated by design so a user can always find their language.
  "src/apps/extension/src/lib/native-language-names.ts",
  // i18n runtime tests: fixtures that prove zh bundles resolve and swap.
  "src/apps/extension/tests/lib/i18n.test.ts",
]);

// Translated documentation carries its language in the filename and lives in
// docs/ (or is a root-level translated README).
const ALLOWED_PATTERNS = [/^docs\/.*\.zh_(CN|TW)\.md$/, /^README\.zh_(CN|TW)\.md$/];

// Han, kana, hangul, and bopomofo scripts, plus the CJK-only blocks that ride
// along with them: punctuation (U+3000-303F), enclosed letters and
// compatibility (U+3200-33FF), compatibility forms (U+FE30-FE4F), and
// fullwidth forms (U+FF00-FFEF). Escaped so this file does not flag itself.
// Keep in sync with the smoke check in tests/ext_test.ts.
const CJK =
  /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Bopomofo}\u3000-\u303F\u3200-\u33FF\uFE30-\uFE4F\uFF00-\uFFEF]/u;

const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
  .split("\0")
  .filter((f) => f.length > 0);

let leaks = 0;
for (const file of files) {
  if (ALLOWED_FILES.has(file) || ALLOWED_PATTERNS.some((p) => p.test(file))) continue;
  const bytes = readFileSync(resolve(root, file));
  if (bytes.includes(0)) continue; // binary (icons, archives)
  const lines = bytes.toString("utf8").split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const hit = CJK.exec(line);
    if (hit) {
      leaks += 1;
      console.error(
        `${file}:${i + 1}: CJK character ${JSON.stringify(hit[0])} outside the allowed files: ${line.trim()}`,
      );
    }
  }
}

if (leaks > 0) {
  console.error(
    `\ncheck-cjk: ${leaks} line(s) with CJK text outside the zh locale files. ` +
      "Canonical strings are English; move zh text into src/apps/extension/src/locales/*.yml " +
      "or a *.zh_CN.md / *.zh_TW.md translated doc.",
  );
  process.exit(1);
}
console.log(`check-cjk: no CJK leaks in ${files.length} tracked files`);
