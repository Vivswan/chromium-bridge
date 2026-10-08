import { afterAll, describe, expect, test } from "bun:test";
import { symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  decodeStrict,
  forbiddenIn,
  type Hit,
  isUtf16,
  loadAllowlist,
  looksBinary,
  parseAllowlist,
  scanFile,
} from "../check-typography";
import { Scratch } from "../lib";

const scratch = new Scratch();
afterAll(() => scratch.remove());

// Every character under test is written as a \u escape, so this file passes
// its own gate (and check-cjk.ts).

const hit = (line: number, column: number, char: string): Hit => ({
  line,
  column,
  char,
  codepoint: `U+${char.codePointAt(0)?.toString(16).toUpperCase().padStart(4, "0")}`,
});

// The scan is a hand-rolled walk over codepoints: the column is a codepoint index (an astral character is
// one column), every hit on a line is reported, a BOM is a hit the decoder must not eat, and the CJK prose
// marks and each range's neighbours stay allowed.
describe("forbiddenIn", () => {
  test.each<[name: string, text: string, hits: Hit[]]>([
    [
      "clean ASCII text has no hits",
      'plain text -- quotes "like this", dashes - and... dots\n',
      [],
    ],
    [
      "an em-dash is flagged with its line and column",
      "line one\nan em\u2014dash here\n",
      [hit(2, 6, "\u2014")],
    ],
    [
      "every occurrence is flagged, not just the first per line",
      "\u201Ccurly\u201D and \u2018curlier\u2019",
      [hit(1, 1, "\u201C"), hit(1, 7, "\u201D"), hit(1, 13, "\u2018"), hit(1, 21, "\u2019")],
    ],
    ["an astral character counts as one column", "\u{1F600}a\u2014b", [hit(1, 3, "\u2014")]],
    [
      "a leading BOM is a hit at 1:1 (the decoder must not eat it)",
      decodeStrict(new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69])),
      [hit(1, 1, "\uFEFF")],
    ],
    ["the CJK prose marks stay allowed", "\u4F60\u597D\u3002\u300C\u5F15\u7528\u300D\u3001", []],
    // Each sits one codepoint past a banned range's edge, or is a symbol the set leaves alone.
    ["neighbours of banned ranges stay allowed", "\u2016\u2017\u2022\u2192\u2260\u2FFF\uFF5F", []],
  ])("%s", (_name, text, hits) => {
    expect(forbiddenIn(text)).toEqual(hits);
  });
});

test("parseAllowlist ignores comments and blanks and keeps exact paths", () => {
  expect(parseAllowlist("# comment\n\ndocs/legacy.md\n  spaced/path.txt  \n")).toEqual(
    new Set(["docs/legacy.md", "spaced/path.txt"]),
  );
});

// The sniffs decide what the gate reads: a null byte means binary, a UTF-16 BOM means text the gate must
// not skip, and the decoder refuses invalid UTF-8 instead of emitting U+FFFD.
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
  const dir = scratch.dir("check-typography-test");

  // A file is scanned by content, never by name, and proven binary content is null, not clean.
  test.each<[name: string, file: string, content: string | Buffer, hits: Hit[] | null]>([
    [
      "a fixture containing an em-dash fails",
      "dirty.md",
      "an em\u2014dash\n",
      [hit(1, 6, "\u2014")],
    ],
    ["a clean fixture passes", "clean.md", "plain ASCII only - no lookalikes\n", []],
    [
      "a text file named .png is scanned",
      "not-an-image.png",
      "sneaky \u2019quote\u2019 in a fake image\n",
      [hit(1, 8, "\u2019"), hit(1, 14, "\u2019")],
    ],
    [
      "binary content (null-byte sniff) is null, not clean",
      "blob",
      Buffer.from([0x00, 0x14, 0x20, 0x00]),
      null,
    ],
  ])("%s", (_name, file, content, hits) => {
    const path = join(dir, file);
    writeFileSync(path, content);
    expect(scanFile(path)).toEqual(hits);
  });

  // Anything unscannable throws, so the caller fails rather than skips. Worktree deletions are excused by
  // main() via `git ls-files --deleted`, not here: an unexplained missing path stays an error.
  type Unscannable = [name: string, prepare: () => string, error: string | undefined];
  const unscannable: Unscannable[] = [
    [
      "UTF-16 content throws instead of being skipped as binary",
      () => {
        const path = join(dir, "utf16.txt");
        writeFileSync(path, Buffer.from([0xff, 0xfe, 0x41, 0x00, 0x42, 0x00]));
        return path;
      },
      "UTF-16",
    ],
    [
      "non-UTF-8 content throws instead of silently passing",
      () => {
        // 0xA0 alone is not valid UTF-8; a lenient decode would turn it into
        // U+FFFD and the no-break space it encodes in latin-1 would go unseen.
        const path = join(dir, "latin1.txt");
        writeFileSync(path, Buffer.from([0x68, 0x69, 0xa0, 0x0a]));
        return path;
      },
      undefined,
    ],
    ["a missing file throws instead of silently passing", () => join(dir, "nope.txt"), undefined],
  ];
  // mode 000 is not enforced on Windows, root reads anything, and raw-byte link names are a unix affair.
  if (process.platform !== "win32") {
    if (process.getuid?.() !== 0) {
      unscannable.push([
        "an unreadable but present file throws instead of silently passing",
        () => {
          const path = join(dir, "unreadable.txt");
          writeFileSync(path, "content\n", { mode: 0o000 });
          return path;
        },
        undefined,
      ]);
    }
    unscannable.push([
      "a symlink whose raw target bytes are invalid UTF-8 throws, not U+FFFD",
      () => {
        const link = join(dir, "raw-link");
        symlinkSync(Buffer.from([0x6e, 0x6f, 0xa0, 0x70, 0x65]), link);
        return link;
      },
      undefined,
    ]);
  }
  test.each(unscannable)("%s", (_name, prepare, error) => {
    const path = prepare();
    if (error === undefined) expect(() => scanFile(path)).toThrow();
    else expect(() => scanFile(path)).toThrow(error);
  });

  test("a symlink is scanned as its link text and never followed", () => {
    const target = join(dir, "target.txt");
    writeFileSync(target, "followed \u2014 content\n");
    const cleanLink = join(dir, "clean-link");
    symlinkSync(target, cleanLink);
    const dirtyLink = join(dir, "dirty-link");
    symlinkSync(join(dir, "no\u2014where"), dirtyLink);
    expect({ clean: scanFile(cleanLink), dirty: scanFile(dirtyLink) }).toEqual({
      clean: [],
      dirty: [hit(1, [...join(dir, "no")].length + 1, "\u2014")],
    });
  });
});

// The allowlist refuses every shape that could smuggle an exemption past the scan.
describe("loadAllowlist (temp fixtures)", () => {
  const dir = scratch.dir("check-typography-allow");
  test.each<
    [name: string, file: string, content: Buffer, outcome: Set<string> | { throws: string }]
  >([
    [
      "a plain UTF-8 list loads",
      "allow",
      Buffer.from("# why: reviewed\ndocs/legacy.md\n"),
      new Set(["docs/legacy.md"]),
    ],
    [
      "NUL bytes are refused (they would make the scan skip the file as binary)",
      "allow-nul",
      Buffer.from("docs/legacy.md\n\u0000", "latin1"),
      { throws: "NUL" },
    ],
    ["invalid UTF-8 is refused", "allow-latin1", Buffer.from([0x64, 0xa0, 0x0a]), { throws: "" }],
  ])("%s", (_name, file, content, outcome) => {
    const path = join(dir, file);
    writeFileSync(path, content);
    if (outcome instanceof Set) expect(loadAllowlist(path)).toEqual(outcome);
    else expect(() => loadAllowlist(path)).toThrow(outcome.throws);
  });

  test("a symlinked allowlist is refused", () => {
    const real = join(dir, "real-allow");
    writeFileSync(real, "docs/legacy.md\n");
    const link = join(dir, "allow-link");
    symlinkSync(real, link);
    expect(() => loadAllowlist(link)).toThrow("symlink");
  });
});
