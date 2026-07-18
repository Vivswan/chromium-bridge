// The site's content registry: every repository markdown doc, imported at
// build time and mapped to a URL slug. The repo's markdown is the single
// source; this site adds no content of its own.
//
// Known limitation (tracked as a follow-up, not load-bearing): relative
// links BETWEEN markdown files (e.g. ./architecture.md) keep pointing at the
// .md paths; use the index for navigation until a rehype link rewrite lands.

import type { MarkdownInstance } from "astro";

type Doc = MarkdownInstance<Record<string, unknown>>;

export interface DocPage {
  slug: string;
  title: string;
  Content: Doc["Content"];
}

const modules = {
  // Repo-root docs (the README and its translations). Vite normalizes each
  // glob key to the shortest relative path, so these arrive with four `../`
  // segments and the docs/ globs below with three; toSlug keys off that
  // depth (verified by the built page list).
  ...import.meta.glob<Doc>("../../../../*.md", { eager: true }),
  // The docs tree: guides, security docs, ADRs, translations.
  ...import.meta.glob<Doc>("../../../../docs/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../docs/security/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../docs/adr/*.md", { eager: true }),
};

// Glob keys come back normalized: repo-root files start with four `../`
// segments, files under docs/ with three. Slugs keep lowercase familiar
// names, and docs/README.md gets its own slug so it cannot collide with the
// repo README.
function toSlug(path: string): string {
  const isRepoRoot = path.startsWith("../../../../");
  const rel = path.replace(/^(\.\.\/)+/, "");
  if (!isRepoRoot && rel === "README.md") return "overview";
  return rel.replace(/\.md$/, "").replace(/^README/, "readme");
}

// Agent-facing instruction files are not user documentation.
const EXCLUDED = new Set(["AGENTS.md", "CLAUDE.md"]);

function toTitle(doc: Doc, slug: string): string {
  const heading = doc.getHeadings().find((h) => h.depth === 1);
  return heading ? heading.text : slug;
}

export const docPages: DocPage[] = Object.entries(modules)
  .filter(([path]) => !EXCLUDED.has(path.replace(/^(\.\.\/)+/, "")))
  .map(([path, doc]) => {
    const slug = toSlug(path);
    return { slug, title: toTitle(doc, slug), Content: doc.Content };
  })
  .sort((a, b) => a.slug.localeCompare(b.slug));
