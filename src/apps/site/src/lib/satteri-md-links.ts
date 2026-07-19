// Repo markdown links point at sibling .md files (./architecture.md); served
// under /docs/<slug>/ those hrefs would 404. This Satteri hast plugin
// resolves each relative .md link against the source file, sends links this
// site renders to their /docs/ route, and other .md targets (source-tree
// READMEs, agent instruction files) to the file on GitHub. Only .md links
// are rewritten; other relative links in docs are left as-is.
import path from "node:path";
import { fileURLToPath } from "node:url";
import { repoPathToSlug } from "./doc-slug";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
const GITHUB_BLOB = "https://github.com/Vivswan/chromium-bridge/blob/main";

export function rewriteMdHref(href: string, fromDir: string, base: string): string | undefined {
  // Leave schemes, root-absolute paths, and pure fragments alone.
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("/") || href.startsWith("#")) {
    return undefined;
  }
  const hash = href.indexOf("#");
  const target = hash === -1 ? href : href.slice(0, hash);
  const fragment = hash === -1 ? "" : href.slice(hash);
  if (!target.endsWith(".md")) return undefined;
  const rel = path.relative(REPO_ROOT, path.resolve(fromDir, target)).split(path.sep).join("/");
  if (rel.startsWith("..")) return undefined;
  const slug = repoPathToSlug(rel);
  if (slug === undefined) return `${GITHUB_BLOB}/${rel}${fragment}`;
  return `${base}${base.endsWith("/") ? "" : "/"}docs/${slug}/${fragment}`;
}

// Structural slices of satteri's Element / HastVisitorContext: just what the
// visitor touches, so this module needs no type-only dependency on the
// processor package.
interface AnchorNode {
  properties?: Record<string, unknown>;
}
interface VisitorContext {
  readonly fileURL: URL | undefined;
  setProperty(node: AnchorNode, key: string, value: unknown): void;
}

export function mdLinksPlugin(base: string) {
  return {
    name: "md-links",
    element: {
      filter: ["a"],
      visit(node: AnchorNode, ctx: VisitorContext): void {
        const href = node.properties?.href;
        if (ctx.fileURL === undefined || typeof href !== "string") return;
        const next = rewriteMdHref(href, path.dirname(fileURLToPath(ctx.fileURL)), base);
        if (next !== undefined) ctx.setProperty(node, "href", next);
      },
    },
  };
}
