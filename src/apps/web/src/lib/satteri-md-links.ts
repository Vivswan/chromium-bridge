// Repo markdown links point at sibling .md files (./architecture.md); served
// under /docs/<slug>/ those hrefs would 404. This Satteri hast plugin
// resolves each relative link against the source file: .md links this site
// renders go to their /docs/ route, other .md targets (source-tree READMEs,
// agent instruction files) go to the file on GitHub, and directory links
// (./adr/) go to the directory listing on GitHub. Anything else relative
// (images, assets) is left as-is.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { repoPathToSlug } from "./doc-slug";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../../..");
const GITHUB_BLOB = "https://github.com/Vivswan/chromium-bridge/blob/main";
const GITHUB_TREE = "https://github.com/Vivswan/chromium-bridge/tree/main";

export function rewriteMdHref(href: string, fromFile: string, base: string): string | undefined {
  const fromDir = path.dirname(fromFile);
  // Leave schemes, root-absolute paths, and pure fragments alone.
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("/") || href.startsWith("#")) {
    return undefined;
  }
  // Split off ?query and #fragment so classification sees only the pathname;
  // both are reattached to whatever URL the link rewrites to.
  const cut = href.search(/[?#]/);
  const target = cut === -1 ? href : href.slice(0, cut);
  const suffix = cut === -1 ? "" : href.slice(cut);
  if (!target.endsWith(".md") && !target.endsWith("/")) return undefined;
  const rel = path.relative(REPO_ROOT, path.resolve(fromDir, target)).split(path.sep).join("/");
  if (rel.startsWith("..") || rel === "") return undefined;
  if (target.endsWith("/")) {
    // A repo directory has no rendered route; send it to the repo tree -
    // exactly where the same link lands when read on GitHub. A trailing
    // slash on anything that is not a real directory is an authoring error
    // that would ship as a guaranteed 404, so fail the build and name it.
    const abs = path.join(REPO_ROOT, rel);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) {
      const source = path.relative(REPO_ROOT, fromFile).split(path.sep).join("/");
      throw new Error(
        `md link "${href}" in ${source}: trailing slash, but "${rel}" is not a repo directory`,
      );
    }
    return `${GITHUB_TREE}/${rel}${suffix}`;
  }
  const slug = repoPathToSlug(rel);
  if (slug === undefined) return `${GITHUB_BLOB}/${rel}${suffix}`;
  return `${base}${base.endsWith("/") ? "" : "/"}docs/${slug}/${suffix}`;
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
        const next = rewriteMdHref(href, fileURLToPath(ctx.fileURL), base);
        if (next !== undefined) ctx.setProperty(node, "href", next);
      },
    },
  };
}
