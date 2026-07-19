// The site's content registry: every repository markdown doc, imported at
// build time and mapped to a URL slug. The repo's markdown is the single
// source; this site adds no content of its own. Relative links between
// markdown files are rewritten to their rendered routes by the
// satteri-md-links plugin (see astro.config.mjs).

import type { MarkdownInstance } from "astro";
import { EXCLUDED, repoPathToSlug } from "./doc-slug";

type Doc = MarkdownInstance<Record<string, unknown>>;

export interface DocPage {
  slug: string;
  title: string;
  Content: Doc["Content"];
}

const modules = {
  // Repo-root docs (the README and its translations).
  ...import.meta.glob<Doc>("../../../../../*.md", { eager: true }),
  // The docs tree: guides, security docs, ADRs, translations.
  ...import.meta.glob<Doc>("../../../../../docs/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../../docs/security/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../../docs/adr/*.md", { eager: true }),
};

// The repo root sits five directories above this file, so every normalized
// glob key starts with five `../` segments; stripping them leaves the
// repo-relative path ("README.md", "docs/architecture.md") that the shared
// slug scheme (doc-slug.ts) names. Every globbed file is in the rendered set
// by construction (verified by the built page list).
function toSlug(path: string): string {
  const rel = path.replace(/^(\.\.\/)+/, "");
  const slug = repoPathToSlug(rel);
  if (slug === undefined) throw new Error(`globbed doc without a slug: ${path}`);
  return slug;
}

function toTitle(doc: Doc, slug: string): string {
  const heading = doc.getHeadings().find((h) => h.depth === 1);
  return heading ? heading.text : slug;
}

export const docPages: DocPage[] = Object.entries(modules)
  .filter(([path]) => !EXCLUDED.has(path.slice(path.lastIndexOf("/") + 1)))
  .map(([path, doc]) => {
    const slug = toSlug(path);
    return { slug, title: toTitle(doc, slug), Content: doc.Content };
  })
  .sort((a, b) => a.slug.localeCompare(b.slug));
