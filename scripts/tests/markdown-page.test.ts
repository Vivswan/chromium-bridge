import { describe, expect, test } from "bun:test";
import { readPage } from "../markdown-page";

// How CommonMark constructs land on lines is an external fact the three consumers (docs-probe,
// check-architecture-page, render-architecture-map) read through this one view: which lines are page text,
// which code node is a fence, and what its body holds. Each case names the construct and pins the whole view.
describe("readPage", () => {
  const view = (markdown: string) => {
    const page = readPage(markdown);
    return {
      text: page.text.map((line) => line !== undefined),
      fences: page.fences.map(({ line, end, mermaid, body }) => ({ line, end, mermaid, body })),
    };
  };
  const cases: ReadonlyArray<
    readonly [name: string, markdown: string, view: ReturnType<typeof view>]
  > = [
    [
      "a fence hides its lines and keeps its body; a mermaid info string marks a diagram",
      "# T\n\n```mermaid\nflowchart LR\n```\n\ntext\n",
      {
        text: [true, true, false, false, false, true, true, true],
        fences: [{ line: 2, end: 4, mermaid: true, body: "flowchart LR" }],
      },
    ],
    [
      "a longer closer holds a shorter fence as text, so the inner diagram is the outer block's body",
      "````markdown\n```mermaid\nx\n```\n````\n",
      {
        text: [false, false, false, false, false, true],
        fences: [{ line: 0, end: 4, mermaid: false, body: "```mermaid\nx\n```" }],
      },
    ],
    [
      "a quoted fence ends with its quote, and a fence in a list item is a fence at its own column",
      "> ```mermaid\n> a\nafter\n\n- ```mermaid\n  b\n  ```\n",
      {
        text: [false, false, true, true, false, false, false, true],
        fences: [
          { line: 0, end: 1, mermaid: true, body: "a" },
          { line: 4, end: 6, mermaid: true, body: "b" },
        ],
      },
    ],
    [
      "indented code is hidden but is no fence; an unclosed fence runs through the last line",
      "p\n\n    code\n\n```\nopen\n",
      {
        text: [true, true, false, true, false, false, false],
        fences: [{ line: 4, end: 6, mermaid: false, body: "open" }],
      },
    ],
    [
      "a comment block hides its lines, indented up to three spaces too; a one-line comment is text",
      "<!-- marker -->\n<!--\nhidden\n-->\n  <!--\n  hidden too\n  -->\n",
      {
        text: [true, false, false, false, false, false, false, true],
        fences: [],
      },
    ],
    [
      "a comment opened inside a paragraph is phrasing, so its lines keep their prose",
      "Demonstrated by: [t](../t.ts) <!--\nnotes\n-->\n",
      { text: [true, true, true, true], fences: [] },
    ],
    [
      "an HTML block that is not a comment is text, fences inside it included",
      "<pre>\n```text\nquoted\n```\n</pre>\n",
      { text: [true, true, true, true, true, true], fences: [] },
    ],
    [
      "CRLF and lone CR line ends are folded, so the parser and the lines agree",
      "a\r\n```\rb\r\n```\r\n",
      {
        text: [true, false, false, false, true],
        fences: [{ line: 1, end: 3, mermaid: false, body: "b" }],
      },
    ],
  ];

  test.each(cases)("%s", (_name, markdown, expected) => {
    expect(view(markdown)).toEqual(expected);
  });
});
