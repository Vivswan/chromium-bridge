// The line-positioned view of a Markdown page that the architecture checks need and Bun's renderer
// does not give: which lines are fenced code (and what each fence holds) and which lines are page
// text. Headings, GENERATED markers, and "Demonstrated by:" lines are read from the text view only,
// so a quoted example never steers a check. A multi-line HTML comment block hides its lines as a
// fence does, since Markdown renders neither; a one-line comment stays text, because the GENERATED
// markers are one-line comments.

import remarkParse from "remark-parse";
import { unified } from "unified";
import { visit } from "unist-util-visit";

export interface Fence {
  /** Zero-based line of the opening fence. */
  line: number;
  /** Zero-based line of the closing fence (or the last line when the fence never closes). */
  end: number;
  /** The info string names mermaid; other fences are text the page quotes. */
  mermaid: boolean;
  body: string;
}

export interface Page {
  lines: readonly string[];
  fences: readonly Fence[];
  /** `lines[i]` when line i is page text, undefined inside a fence or a comment block. */
  text: ReadonlyArray<string | undefined>;
}

const parser = unified().use(remarkParse);

/**
 * The parser decides what is code and what is a comment (CommonMark: a closer at least as long as its
 * opener, a quoted fence that ends with its quote, an inline ```mermaid``` run that is not a fence); this
 * view only maps its nodes back onto lines. A fence body is the node's value, with the opener's
 * indentation and the quote markers already dropped. CRLF and lone CR line ends are folded first, so the
 * parser and the line array count the same lines.
 */
export function readPage(markdown: string): Page {
  const normalized = markdown.replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  const fences: Fence[] = [];
  const hidden = new Array<boolean>(lines.length).fill(false);
  const hide = (line: number, end: number): void => {
    for (let i = line; i <= end; i++) hidden[i] = true;
  };
  visit(parser.parse(normalized), (node, _index, parent) => {
    if (node.type !== "code" && node.type !== "html") return;
    if (node.position === undefined) throw new Error("markdown-page: a node without a position");
    const { start, end } = node.position;
    const line = start.line - 1;
    if (node.type === "code") {
      hide(line, end.line - 1);
      // mdast does not say whether a code node was fenced or indented: the source at the node's own first
      // column (past any quote or list marker) does.
      const opener = (lines[line] ?? "").slice(start.column - 1);
      if (/^(?:`{3,}|~{3,})/.test(opener)) {
        fences.push({
          line,
          end: end.line - 1,
          mermaid: node.lang === "mermaid" && !node.meta,
          body: node.value,
        });
      }
      return;
    }
    // Only a comment that is a block of its own (parent root, quote, or list item) hides lines; one opened
    // inside a paragraph is phrasing and its lines keep their prose. Other HTML blocks are text.
    const block =
      parent?.type === "root" || parent?.type === "blockquote" || parent?.type === "listItem";
    if (block && node.value.trimStart().startsWith("<!--") && end.line > start.line) {
      hide(line, end.line - 1);
    }
  });
  return { lines, fences, text: lines.map((line, i) => (hidden[i] ? undefined : line)) };
}

export function linkFile(link: string): string {
  const bare = link.split("#")[0]?.split("?")[0] ?? "";
  try {
    return decodeURIComponent(bare);
  } catch {
    return bare;
  }
}
