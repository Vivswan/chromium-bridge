// The site's content registry: every repository markdown doc, imported at
// build time and mapped to a URL slug. The repo's markdown is the single
// source; this site adds no content of its own. Relative links between
// markdown files are rewritten to their rendered routes by the
// satteri-md-links plugin (see astro.config.mjs).

import type { MarkdownInstance } from "astro";
import { ROOT_DOCS, repoPathToSlug } from "./doc-slug";

type Doc = MarkdownInstance<Record<string, unknown>>;

export interface DocPage {
  slug: string;
  title: string;
  Content: Doc["Content"];
}

const modules = {
  // Repo-root markdown; only the ROOT_DOCS allowlist (doc-slug.ts) renders.
  ...import.meta.glob<Doc>("../../../../../*.md", { eager: true }),
  // The docs tree: guides, security docs, ADRs, translations.
  ...import.meta.glob<Doc>("../../../../../docs/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../../docs/security/*.md", { eager: true }),
  ...import.meta.glob<Doc>("../../../../../docs/adr/*.md", { eager: true }),
};

// The repo root sits five directories above this file, so every normalized
// glob key starts with five `../` segments; stripping them leaves the
// repo-relative path ("README.md", "docs/architecture.md") that the shared
// slug scheme (doc-slug.ts) names.
function toRepoPath(path: string): string {
  return path.replace(/^(\.\.\/)+/, "");
}

// Tracked root files that are agent instructions, not user documentation.
// They are outside ROOT_DOCS like anything else, so they never render; this
// set only keeps them out of the unlisted-file note below.
const AGENT_FILES = new Set(["AGENTS.md", "CLAUDE.md"]);

function toTitle(doc: Doc, slug: string): string {
  const heading = doc.getHeadings().find((h) => h.depth === 1);
  return heading ? heading.text : slug;
}

export const docPages: DocPage[] = Object.entries(modules)
  .flatMap(([path, doc]): DocPage[] => {
    const rel = toRepoPath(path);
    const slug = repoPathToSlug(rel);
    if (slug === undefined) {
      // Fail closed, visibly: a root file outside the ROOT_DOCS allowlist
      // (a scratch note in a dirty checkout, or a new doc nobody listed
      // yet) is not shipped. A note rather than a hard failure, because
      // untracked working notes are normal in a local checkout and the
      // allowlist already guarantees they cannot publish.
      if (!AGENT_FILES.has(rel)) {
        console.warn(
          `[docs] not rendering ${rel}: not in the ROOT_DOCS allowlist (doc-slug.ts); add it there to ship it`,
        );
      }
      return [];
    }
    return [{ slug, title: toTitle(doc, slug), Content: doc.Content }];
  })
  .sort((a, b) => a.slug.localeCompare(b.slug));

// Guard the other direction of the allowlist: every root doc the site
// promises to render must actually be in the checkout, or the build fails
// rather than quietly shipping without it.
const globbed = new Set(Object.keys(modules).map(toRepoPath));
for (const doc of ROOT_DOCS) {
  if (!globbed.has(doc)) {
    throw new Error(`allowlisted root doc missing from the checkout: ${doc}`);
  }
}
