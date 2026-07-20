// The slug scheme for rendered repo docs, shared by the content registry
// (docs.ts) and the md-link rewriter (satteri-md-links.ts) so the two can
// never disagree about which route a markdown file gets.

// The repo-root docs the site ships. This is an allowlist on purpose: the
// root glob in docs.ts picks up whatever sits in the checkout, including
// untracked scratch notes, so an unrecognized root file must fail closed
// (not rendered) instead of publishing by accident. Rendering a new root
// doc means adding it here, deliberately.
export const ROOT_DOCS = new Set([
  "README.md",
  "README.zh_CN.md",
  "README.zh_TW.md",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "GOVERNANCE.md",
]);

// Maps a repo-relative markdown path ("docs/architecture.md") to its /docs/
// route slug, or undefined when the site does not render that file. The
// rendered set mirrors the globs in docs.ts: the allowlisted repo-root docs
// plus docs/, docs/security/, and docs/adr/.
export function repoPathToSlug(rel: string): string | undefined {
  if (!rel.endsWith(".md")) return undefined;
  if (rel === "docs/README.md") return "overview";
  if (!rel.startsWith("docs/")) {
    if (!ROOT_DOCS.has(rel)) return undefined;
    return rel.replace(/\.md$/, "").replace(/^README/, "readme");
  }
  const scoped = rel.slice("docs/".length);
  const dir = scoped.includes("/") ? scoped.slice(0, scoped.lastIndexOf("/")) : "";
  if (!["", "security", "adr"].includes(dir)) return undefined;
  return scoped.replace(/\.md$/, "").replace(/^README/, "readme");
}
