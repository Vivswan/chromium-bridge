import { describe, expect, test } from "bun:test";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  decodeStrict,
  FORBIDDEN_RANGES,
  forbiddenIn,
  isUtf16,
  loadAllowlist,
  looksBinary,
  parseAllowlist,
  scanFile,
} from "./check-typography";

// Every character under test is written as a \u escape, so this file passes
// its own gate (and check-cjk.ts).

describe("forbiddenIn", () => {
  test("clean ASCII text has no hits", () => {
    expect(forbiddenIn('plain text -- quotes "like this", dashes - and... dots\n')).toEqual([]);
  });

  test("flags an em-dash with its line, column, and codepoint", () => {
    const hits = forbiddenIn("line one\nan em\u2014dash here\n");
    expect(hits).toEqual([{ line: 2, column: 6, char: "\u2014", codepoint: "U+2014" }]);
  });

  test("flags every occurrence, not just the first per line", () => {
    const hits = forbiddenIn("\u201Ccurly\u201D and \u2018curlier\u2019");
    expect(hits.map((h) => h.codepoint)).toEqual(["U+201C", "U+201D", "U+2018", "U+2019"]);
  });

  test("every codepoint of every banned range is a hit", () => {
    for (const [first, last] of FORBIDDEN_RANGES) {
      for (let cp = first; cp <= last; cp++) {
        const hits = forbiddenIn(`x${String.fromCodePoint(cp)}y`);
        expect(hits).toHaveLength(1);
        expect(hits[0]?.codepoint).toBe(`U+${cp.toString(16).toUpperCase().padStart(4, "0")}`);
      }
    }
  });

  test("astral characters count as one column and are not misflagged", () => {
    // U+1F600 (emoji) before an em-dash: the dash sits at codepoint column 3.
    const hits = forbiddenIn("\u{1F600}a\u2014b");
    expect(hits).toEqual([{ line: 1, column: 3, char: "\u2014", codepoint: "U+2014" }]);
  });

  test("a leading BOM is a hit at 1:1 (the decoder must not eat it)", () => {
    expect(forbiddenIn(decodeStrict(new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69])))).toEqual([
      { line: 1, column: 1, char: "\uFEFF", codepoint: "U+FEFF" },
    ]);
  });

  test("the CJK prose marks stay allowed (they are not in the set)", () => {
    // U+3001 U+3002 U+300C U+300D: ideographic comma/full stop and corner
    // brackets - legitimate in CJK prose, deliberately not banned.
    expect(forbiddenIn("\u4F60\u597D\u3002\u300C\u5F15\u7528\u300D\u3001")).toEqual([]);
  });

  test("neighbours of banned ranges stay allowed", () => {
    // U+2016 (after U+2000-2015), U+2017, U+2022 bullet, U+2192 arrow,
    // U+2260 not-equal, U+2FFF (before U+3000), U+FF5F (after U+FF5E).
    expect(forbiddenIn("\u2016\u2017\u2022\u2192\u2260\u2FFF\uFF5F")).toEqual([]);
  });
});

describe("parseAllowlist", () => {
  test("ignores comments and blanks, keeps exact paths", () => {
    const set = parseAllowlist("# comment\n\ndocs/legacy.md\n  spaced/path.txt  \n");
    expect(set).toEqual(new Set(["docs/legacy.md", "spaced/path.txt"]));
  });

  test("matching is exact, never prefix (the original action's footgun)", () => {
    const set = parseAllowlist("docs\n");
    expect(set.has("docs")).toBe(true);
    expect(set.has("docs/anything.md")).toBe(false);
  });
});

describe("content sniffing", () => {
  test("null byte means binary", () => {
    expect(looksBinary(new Uint8Array([0x68, 0x00, 0x69]))).toBe(true);
    expect(looksBinary(new TextEncoder().encode("plain text"))).toBe(false);
  });

  test("UTF-16 BOMs are recognized as text-not-binary", () => {
    expect(isUtf16(new Uint8Array([0xfe, 0xff, 0x00, 0x41]))).toBe(true);
    expect(isUtf16(new Uint8Array([0xff, 0xfe, 0x41, 0x00]))).toBe(true);
    expect(isUtf16(new TextEncoder().encode("plain"))).toBe(false);
  });

  test("decodeStrict rejects invalid UTF-8 instead of emitting U+FFFD", () => {
    expect(() => decodeStrict(new Uint8Array([0x68, 0xa0]))).toThrow();
  });
});

describe("scanFile (temp fixtures, never the repo)", () => {
  const dir = mkdtempSync(join(tmpdir(), "check-typography-test-"));

  test("fails a fixture containing an em-dash", () => {
    const path = join(dir, "dirty.md");
    writeFileSync(path, "an em\u2014dash\n");
    expect(scanFile(path)).toEqual([{ line: 1, column: 6, char: "\u2014", codepoint: "U+2014" }]);
  });

  test("passes a clean fixture", () => {
    const path = join(dir, "clean.md");
    writeFileSync(path, "plain ASCII only - no lookalikes\n");
    expect(scanFile(path)).toEqual([]);
  });

  test("scans by content, not extension: a text file named .png is scanned", () => {
    const path = join(dir, "not-an-image.png");
    writeFileSync(path, "sneaky \u2019quote\u2019 in a fake image\n");
    expect(scanFile(path)?.map((h) => h.codepoint)).toEqual(["U+2019", "U+2019"]);
  });

  test("skips binary content (null-byte sniff) as null, not as clean", () => {
    const path = join(dir, "blob");
    writeFileSync(path, Buffer.from([0x00, 0x14, 0x20, 0x00]));
    expect(scanFile(path)).toBeNull();
  });

  test("throws on UTF-16 content instead of skipping it as binary", () => {
    const path = join(dir, "utf16.txt");
    writeFileSync(path, Buffer.from([0xff, 0xfe, 0x41, 0x00, 0x42, 0x00]));
    expect(() => scanFile(path)).toThrow("UTF-16");
  });

  test("throws on non-UTF-8 content instead of silently passing", () => {
    const path = join(dir, "latin1.txt");
    // 0xA0 alone is not valid UTF-8; a lenient decode would turn it into
    // U+FFFD and the no-break space it encodes in latin-1 would go unseen.
    writeFileSync(path, Buffer.from([0x68, 0x69, 0xa0, 0x0a]));
    expect(() => scanFile(path)).toThrow();
  });

  test("a symlink is scanned as its link text and never followed", () => {
    // Target holds a banned char; the link text is clean: no hits. And a
    // link whose TEXT carries a banned char is flagged even when dangling.
    const target = join(dir, "target.txt");
    writeFileSync(target, "followed \u2014 content\n");
    const cleanLink = join(dir, "clean-link");
    symlinkSync(target, cleanLink);
    expect(scanFile(cleanLink)).toEqual([]);
    const dirtyLink = join(dir, "dirty-link");
    symlinkSync(join(dir, "no\u2014where"), dirtyLink);
    expect(scanFile(dirtyLink)?.map((h) => h.codepoint)).toEqual(["U+2014"]);
  });

  test("throws on a missing file instead of silently passing", () => {
    // Worktree deletions are excused by main() via `git ls-files --deleted`,
    // not here: an unexplained missing path stays an error.
    expect(() => scanFile(join(dir, "nope.txt"))).toThrow();
  });

  test("throws on an unreadable but present file instead of silently passing", () => {
    if (process.platform === "win32") return; // mode 000 is not enforced there
    if (process.getuid?.() === 0) return; // root reads anything
    const path = join(dir, "unreadable.txt");
    writeFileSync(path, "content\n", { mode: 0o000 });
    expect(() => scanFile(path)).toThrow();
  });

  test("a symlink whose raw target bytes are invalid UTF-8 throws, not U+FFFD", () => {
    if (process.platform === "win32") return; // raw-byte link names are a unix affair
    const link = join(dir, "raw-link");
    symlinkSync(Buffer.from([0x6e, 0x6f, 0xa0, 0x70, 0x65]), link);
    expect(() => scanFile(link)).toThrow();
  });
});

describe("loadAllowlist (temp fixtures)", () => {
  const dir = mkdtempSync(join(tmpdir(), "check-typography-allow-"));

  test("loads a plain UTF-8 list", () => {
    const path = join(dir, "allow");
    writeFileSync(path, "# why: reviewed\ndocs/legacy.md\n");
    expect(loadAllowlist(path)).toEqual(new Set(["docs/legacy.md"]));
  });

  test("refuses a symlinked allowlist", () => {
    const real = join(dir, "real-allow");
    writeFileSync(real, "docs/legacy.md\n");
    const link = join(dir, "allow-link");
    symlinkSync(real, link);
    expect(() => loadAllowlist(link)).toThrow("symlink");
  });

  test("refuses NUL bytes (they would make the scan skip the file as binary)", () => {
    const path = join(dir, "allow-nul");
    writeFileSync(path, Buffer.from("docs/legacy.md\n\u0000", "latin1"));
    expect(() => loadAllowlist(path)).toThrow("NUL");
  });

  test("refuses invalid UTF-8", () => {
    const path = join(dir, "allow-latin1");
    writeFileSync(path, Buffer.from([0x64, 0xa0, 0x0a]));
    expect(() => loadAllowlist(path)).toThrow();
  });
});
