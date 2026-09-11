// Repo markdown links are relative repo paths; served under /docs/<slug>/
// they would 404. This Satteri hast plugin resolves each one against its
// source file: a page this site renders gets its /docs/ route, anything else
// in the repo goes where the same link lands on GitHub, and a link to nothing
// in the repo fails the build by name rather than shipping a 404.
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
  const rel = path.relative(REPO_ROOT, path.resolve(fromDir, target)).split(path.sep).join("/");
  if (rel.startsWith("..") || rel === "") return undefined;
  const abs = path.join(REPO_ROOT, rel);
  const source = path.relative(REPO_ROOT, fromFile).split(path.sep).join("/");
  if (target.endsWith("/")) {
    // A repo directory has no rendered route; send it to the repo tree -
    // exactly where the same link lands when read on GitHub.
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) {
      throw new Error(
        `md link "${href}" in ${source}: trailing slash, but "${rel}" is not a repo directory`,
      );
    }
    return `${GITHUB_TREE}/${rel}${suffix}`;
  }
  if (!fs.existsSync(abs) || !fs.statSync(abs).isFile()) {
    throw new Error(`md link "${href}" in ${source}: "${rel}" is not a file in the repo`);
  }
  const slug = target.endsWith(".md") ? repoPathToSlug(rel) : undefined;
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
