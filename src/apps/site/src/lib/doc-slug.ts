// The slug scheme for rendered repo docs, shared by the content registry
// (docs.ts) and the md-link rewriter (satteri-md-links.ts) so the two can
// never disagree about which route a markdown file gets.

// Agent-facing instruction files are not user documentation, wherever they
// sit in the tree. HANDOFF/CONSOLIDATION-AUDIT are uncommitted working notes
// that would otherwise render from a local checkout's repo-root glob.
export const EXCLUDED = new Set(["AGENTS.md", "CLAUDE.md", "HANDOFF.md", "CONSOLIDATION-AUDIT.md"]);

// Maps a repo-relative markdown path ("docs/architecture.md") to its /docs/
// route slug, or undefined when the site does not render that file. The
// rendered set mirrors the globs in docs.ts: repo-root *.md plus docs/,
// docs/security/, and docs/adr/.
export function repoPathToSlug(rel: string): string | undefined {
  const name = rel.slice(rel.lastIndexOf("/") + 1);
  if (!rel.endsWith(".md") || EXCLUDED.has(name)) return undefined;
  if (rel === "docs/README.md") return "overview";
  const scoped = rel.startsWith("docs/") ? rel.slice("docs/".length) : rel;
  const dir = scoped.includes("/") ? scoped.slice(0, scoped.lastIndexOf("/")) : "";
  const renderedDirs = rel.startsWith("docs/") ? ["", "security", "adr"] : [""];
  if (!renderedDirs.includes(dir)) return undefined;
  return scoped.replace(/\.md$/, "").replace(/^README/, "readme");
}
