#!/usr/bin/env bun

// Typography gate: no typographic look-alike characters (curly quotes,
// em-dashes, invisible unicode) anywhere in the tree - plain ASCII
// punctuation only. A look-alike is at best noise and at worst an attack
// vector (an invisible bidi override or a homoglyph in a security-relevant
// string reads differently to a human than to a parser).
//
// Local replacement for the retired Vivswan/repo-platform check-typography
// action, enforcing the same rules:
//   - every git-tracked path is scanned - content AND filename (a bidi mark
//     can hide in a name as well as in a line);
//   - the FORBIDDEN set below is banned everywhere;
//   - the four CJK marks it deliberately omits (U+3001 U+3002 U+300C U+300D)
//     stay usable in CJK prose - whole-script containment is check-cjk.ts's
//     job, not this one's;
//   - .typography-allow exempts exact repo-relative paths (one per line,
//     # comments). Exact, not prefix: the original action's prefix matching
//     could silently exempt a whole subtree from a one-file entry. The
//     allowlist can exempt anything except itself.
//
// Fail closed: the only silent skips are proven-binary content (a null byte
// in the leading window) and a path git itself reports as deleted from the
// worktree (no bytes exist to hide anything). Everything else that cannot be
// scanned - unreadable, not valid UTF-8, UTF-16, missing without a recorded
// deletion - is an error, never a pass: a checker that shrugs at unreadable
// input is a bypass, not a gate. Extensions are deliberately NOT trusted;
// a text file named payload.png must still be scanned.
//
// Dependency-free (Bun + node builtins), so it runs without a bun install.

import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Banned codepoints, as inclusive [first, last] ranges. All escaped so this
 * file never flags itself. Kept identical to the retired action's set. */
export const FORBIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x00a0, 0x00a0], // no-break space
  [0x00ab, 0x00ab], // left guillemet
  [0x00ad, 0x00ad], // soft hyphen
  [0x00b1, 0x00b1], // plus-minus sign
  [0x00b4, 0x00b4], // acute accent (apostrophe look-alike)
  [0x00bb, 0x00bb], // right guillemet
  [0x00d7, 0x00d7], // multiplication sign
  [0x00f7, 0x00f7], // division sign
  [0x02bc, 0x02bc], // modifier letter apostrophe
  [0x2000, 0x2015], // unicode spaces, hyphens, en/em dashes, horizontal bar
  [0x2018, 0x201f], // curly single and double quotes
  [0x2026, 0x2026], // horizontal ellipsis
  [0x2028, 0x202f], // line/para separators, bidi embedding, narrow nbsp
  [0x2032, 0x2037], // primes and reversed primes
  [0x2039, 0x203a], // single guillemets
  [0x2060, 0x2060], // word joiner
  [0x2066, 0x2069], // bidi isolates
  [0x2212, 0x2212], // minus sign
  [0x2248, 0x2248], // almost equal to
  [0x3000, 0x3000], // ideographic space
  [0xfeff, 0xfeff], // BOM / zero-width no-break space
  [0xff01, 0xff5e], // fullwidth ASCII variants
];

function isForbidden(codepoint: number): boolean {
  return FORBIDDEN_RANGES.some(([first, last]) => codepoint >= first && codepoint <= last);
}

/** Whether the content is binary: a null byte in the first 8 KiB (the same
 * sniff git uses). UTF-16 text also trips this, which is why the caller
 * checks for UTF-16 BOMs FIRST - a UTF-16 source file must be converted, not
 * skipped as if it were an icon. */
export function looksBinary(bytes: Uint8Array): boolean {
  return bytes.subarray(0, 8192).includes(0);
}

/** Whether the content announces itself as UTF-16 (BOM). Such a file is
 * text - exactly what this gate exists to read - so it is an error upstream,
 * never a binary skip. */
export function isUtf16(bytes: Uint8Array): boolean {
  return (
    bytes.length >= 2 &&
    ((bytes[0] === 0xfe && bytes[1] === 0xff) || (bytes[0] === 0xff && bytes[1] === 0xfe))
  );
}

export interface Hit {
  /** 1-based line number. */
  line: number;
  /** 1-based column (in codepoints). */
  column: number;
  /** The offending character. */
  char: string;
  /** "U+XXXX" form of the codepoint. */
  codepoint: string;
}

/** Scan decoded text for forbidden codepoints. Every occurrence is reported,
 * not just the first per line. Iteration is by codepoint (for..of), so an
 * astral character counts as one column and can never split into surrogate
 * halves that dodge the ranges. */
export function forbiddenIn(text: string): Hit[] {
  const hits: Hit[] = [];
  let line = 1;
  let column = 1;
  for (const char of text) {
    if (char === "\n") {
      line += 1;
      column = 1;
      continue;
    }
    const codepoint = char.codePointAt(0);
    if (codepoint !== undefined && isForbidden(codepoint)) {
      hits.push({
        line,
        column,
        char,
        codepoint: `U+${codepoint.toString(16).toUpperCase().padStart(4, "0")}`,
      });
    }
    column += 1;
  }
  return hits;
}

/** Parse .typography-allow: one exact repo-relative path per line, blank
 * lines and #-comment lines ignored. */
export function parseAllowlist(text: string): Set<string> {
  const allowed = new Set<string>();
  for (const raw of text.split("\n")) {
    const entry = raw.trim();
    if (entry === "" || entry.startsWith("#")) continue;
    allowed.add(entry);
  }
  return allowed;
}

/** fatal: a byte sequence that is not UTF-8 must error, not decode to U+FFFD
 * and slide through. ignoreBOM: a leading U+FEFF must be SEEN (it is in the
 * forbidden set), not silently stripped by the decoder. */
export function decodeStrict(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
}

/** Scan one tracked path on disk. Returns its content hits, or null when the
 * content is proven binary (null-byte sniff). A symlink is scanned as its
 * tracked content - the link TEXT via readlink - never followed (the target
 * may be outside the repo, or the tracked-content bytes could differ from
 * what a follow reads). Throws on anything unscannable: missing, unreadable,
 * UTF-16, or not valid UTF-8 - the caller turns that into a failure, never
 * a skip. */
export function scanFile(absPath: string): Hit[] | null {
  if (lstatSync(absPath).isSymbolicLink()) {
    // Raw link bytes, strictly decoded: a lenient readlink would smear
    // invalid UTF-8 into U+FFFD and hide what the link really says.
    return forbiddenIn(decodeStrict(readlinkSync(absPath, { encoding: "buffer" })));
  }
  const bytes = readFileSync(absPath);
  if (isUtf16(bytes)) {
    throw new Error("UTF-16 text (BOM detected); convert it to UTF-8 so it can be scanned");
  }
  if (looksBinary(bytes)) return null;
  return forbiddenIn(decodeStrict(bytes));
}

/** Load the exemption list, refusing every shape that could smuggle an
 * exemption past the scan: a symlinked allowlist (its exemptions would apply
 * while only its link text gets scanned), NUL bytes (the general scan would
 * classify the file as binary and skip its content), and invalid UTF-8. */
export function loadAllowlist(absPath: string): Set<string> {
  if (lstatSync(absPath).isSymbolicLink()) {
    throw new Error("must be a regular file, not a symlink");
  }
  const bytes = readFileSync(absPath);
  if (bytes.includes(0)) {
    throw new Error("contains NUL bytes; the allowlist must be plain UTF-8 text");
  }
  return parseAllowlist(decodeStrict(bytes));
}

if (import.meta.main) {
  const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
  // -z: NUL-delimited raw path bytes (no quoting layer). Decoded strictly,
  // entry by entry: a path whose bytes are not valid UTF-8 is an error, not
  // a U+FFFD mush that then fails to open and vanishes.
  const pathBytes = execFileSync("git", ["ls-files", "-z"], { cwd: root });
  // Paths git records as deleted from the worktree (a pending `git rm` is
  // still listed by ls-files): recorded state, nothing on disk to scan.
  // Decoded with the same strict rule as the primary list; an undecodable
  // entry is simply not excusable (and errors via the primary list anyway).
  const deleted = new Set<string>();
  for (const raw of splitNul(execFileSync("git", ["ls-files", "-z", "--deleted"], { cwd: root }))) {
    try {
      deleted.add(decodeStrict(raw));
    } catch {
      // Reported when the primary list hits the same bytes.
    }
  }

  const errors: string[] = [];
  const files: string[] = [];
  for (const raw of splitNul(pathBytes)) {
    try {
      files.push(decodeStrict(raw));
    } catch {
      errors.push(`tracked path with non-UTF-8 bytes: ${JSON.stringify(raw.toString("latin1"))}`);
    }
  }

  const allowFile = ".typography-allow";
  let allowed = new Set<string>();
  if (files.includes(allowFile) && !deleted.has(allowFile)) {
    try {
      allowed = loadAllowlist(resolve(root, allowFile));
    } catch (err) {
      errors.push(`${allowFile}: not a scannable exemption list (${err})`);
    }
    // The gate's own configuration is never exempt from the gate.
    allowed.delete(allowFile);
    // Allowlist rot: an entry naming an untracked path exempts nothing and
    // usually means a typo or a stale rename - surface it.
    for (const entry of allowed) {
      if (!files.includes(entry)) {
        errors.push(`${allowFile} lists "${entry}", which is not a tracked file`);
      }
    }
  }

  let hitCount = 0;
  let scanned = 0;
  for (const file of files) {
    // The NAME is scanned even for allowed and binary files.
    for (const hit of forbiddenIn(file)) {
      hitCount += 1;
      console.error(`${file}: forbidden ${hit.codepoint} in the file NAME itself`);
    }
    if (allowed.has(file) || deleted.has(file)) continue;
    let hits: Hit[] | null;
    try {
      hits = scanFile(resolve(root, file));
    } catch (err) {
      errors.push(`${file}: cannot be scanned (${err}); refusing to skip it`);
      continue;
    }
    if (hits === null) continue; // proven binary
    scanned += 1;
    for (const hit of hits) {
      hitCount += 1;
      console.error(
        `${file}:${hit.line}:${hit.column}: forbidden ${hit.codepoint} ${JSON.stringify(hit.char)} - use plain ASCII punctuation`,
      );
    }
  }

  for (const e of errors) console.error(`check-typography: ${e}`);
  if (hitCount > 0 || errors.length > 0) {
    console.error(
      `\ncheck-typography: ${hitCount} forbidden character(s), ${errors.length} error(s). ` +
        "Replace look-alike punctuation with ASCII; exempt a path only via an " +
        "exact entry in .typography-allow with a reviewed reason.",
    );
    process.exit(1);
  }
  console.log(`check-typography: ${scanned} text files clean (${files.length} tracked paths)`);
}

/** Split a NUL-delimited buffer into per-entry buffers (no decoding). */
function splitNul(bytes: Buffer): Buffer[] {
  const parts: Buffer[] = [];
  let start = 0;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) {
      if (i > start) parts.push(bytes.subarray(start, i));
      start = i + 1;
    }
  }
  if (start < bytes.length) parts.push(bytes.subarray(start));
  return parts;
}
