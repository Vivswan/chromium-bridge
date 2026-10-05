// The line-positioned view of a Markdown page that the architecture checks need and Bun's renderer
// does not give: which lines are fenced code (and what each fence holds) and which lines are page
// text. Headings, GENERATED markers, and "Demonstrated by:" lines are read from the text view only,
// so a quoted example never steers a check. A multi-line HTML comment block hides its lines as a
// fence does, since Markdown renders neither; a one-line comment stays text, because the GENERATED
// markers are one-line comments.

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

// A fence may sit inside block quotes (each marker up to three spaces in, then `>` and an optional
// space), then up to three spaces of indent, as Markdown allows; four spaces make indented code, which
// is quoted text. The closer carries the same quote depth.
const QUOTE_MARKER = " {0,3}>[ ]?";
const FENCE_OPEN = new RegExp(`^((?:${QUOTE_MARKER})*)( {0,3})(\`{3,}|~{3,})(.*)$`);
const MERMAID_INFO = /^\s*mermaid\s*$/;
// A comment block opens on a line starting with <!-- that does not also close it, and runs through
// the first line holding -->.
const COMMENT_OPEN = /^ {0,3}<!--/;
// Indented code: four spaces or a tab after a blank line, or continuing such a block. Inside a list
// item the same indent is list content; the docs rules forbid nested lists, so the page sees none.
const INDENTED = /^( {4}|\t)/;

/**
 * A fence runs to a closer at least as long as its opener, so a ```mermaid example nested inside a
 * ````markdown block is that block's text, not a diagram. The body drops the indentation the opener
 * has. CRLF line ends are folded first, so every reader counts the same lines.
 */
export function readPage(markdown: string): Page {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const fences: Fence[] = [];
  const hidden = new Array<boolean>(lines.length).fill(false);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index] ?? "";
    const previous = index === 0 ? "" : (lines[index - 1] ?? "");
    if (INDENTED.test(line) && (previous.trim() === "" || hidden[index - 1] === true)) {
      hidden[index] = true;
      continue;
    }
    if (COMMENT_OPEN.test(line) && !line.includes("-->")) {
      let cursor = index;
      while (cursor < lines.length && !(lines[cursor] ?? "").includes("-->")) {
        hidden[cursor] = true;
        cursor += 1;
      }
      if (cursor < lines.length) hidden[cursor] = true;
      index = cursor;
      continue;
    }
    const open = FENCE_OPEN.exec(line);
    if (open === null) continue;
    // Block-quote depth is what carries over line to line; the space after each `>` is optional on every line.
    const depth = (open[1] ?? "").split(">").length - 1;
    const quotePrefix = new RegExp(`^(?:${QUOTE_MARKER}){${depth}}`);
    const indent = open[2] ?? "";
    const ticks = open[3] ?? "```";
    // A closer repeats the opener's marker character at least as many times, at the same quote depth and at most three spaces in.
    const close = new RegExp(
      `^(?:${QUOTE_MARKER}){${depth}} {0,3}${ticks[0] === "~" ? "~" : "`"}{${ticks.length},}[ \\t]*$`,
    );
    const body: string[] = [];
    let cursor = index + 1;
    // Inside a block quote the fence ends with the quote: Markdown closes the container, and the fence
    // with it, at the first line without the quote marker, closer or not.
    const quoted = (text: string): boolean => depth === 0 || quotePrefix.test(text);
    while (
      cursor < lines.length &&
      quoted(lines[cursor] ?? "") &&
      !close.test(lines[cursor] ?? "")
    ) {
      const text = (lines[cursor] ?? "").replace(quotePrefix, "");
      body.push(text.startsWith(indent) ? text.slice(indent.length) : text);
      cursor += 1;
    }
    const closedByMarker = cursor < lines.length && close.test(lines[cursor] ?? "");
    const end = closedByMarker ? cursor : cursor - 1;
    for (let i = index; i <= end; i++) hidden[i] = true;
    fences.push({
      line: index,
      end,
      mermaid: MERMAID_INFO.test(open[4] ?? ""),
      body: body.join("\n"),
    });
    index = end;
  }
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
