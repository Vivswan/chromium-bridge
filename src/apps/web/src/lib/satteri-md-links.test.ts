// Every relative repo link lands in exactly one of: a /docs/ route, GitHub,
// untouched, or a build failure. A link the rewriter leaves untouched by
// mistake ships as a 404, which is what these cases guard.
import { describe, expect, test } from "bun:test";
import path from "node:path";
import { rewriteMdHref } from "./satteri-md-links";

const REPO_ROOT = path.resolve(import.meta.dir, "../../../../..");
const from = (rel: string) => path.join(REPO_ROOT, rel);
const BLOB = "https://github.com/Vivswan/chromium-bridge/blob/main";
const TREE = "https://github.com/Vivswan/chromium-bridge/tree/main";

describe("rewriteMdHref", () => {
  test.each([
    // [href, source file, expected]
    ["./architecture.md#11-contracts", "docs/cli.md", "/cb/docs/architecture/#11-contracts"],
    ["../src/packages/core/src/error.rs", "docs/cli.md", `${BLOB}/src/packages/core/src/error.rs`],
    ["./Cargo.toml", "README.md", `${BLOB}/Cargo.toml`],
    ["./NOTICE", "README.md", `${BLOB}/NOTICE`],
    [
      "ISSUE_TEMPLATE/security-change.yml",
      ".github/SECURITY.md",
      `${BLOB}/.github/ISSUE_TEMPLATE/security-change.yml`,
    ],
    ["./adr/", "docs/architecture.md", `${TREE}/docs/adr`],
    ["../.github/agents.md", "docs/cli.md", `${BLOB}/.github/agents.md`],
  ])("%s from %s -> %s", (href, source, expected) => {
    expect(rewriteMdHref(href, from(source), "/cb/")).toBe(expected);
  });

  test.each([
    ["https://example.com/x.rs", "docs/cli.md"],
    ["/absolute/path.md", "docs/cli.md"],
    ["#fragment-only", "docs/cli.md"],
    ["../../outside-the-repo.md", "README.md"],
  ])("%s from %s is left alone", (href, source) => {
    expect(rewriteMdHref(href, from(source), "/cb/")).toBeUndefined();
  });

  test.each([
    [
      "./no-such-file.rs",
      "docs/cli.md",
      'md link "./no-such-file.rs" in docs/cli.md: "docs/no-such-file.rs" is not a file in the repo',
    ],
    [
      "./no-such-dir/",
      "docs/cli.md",
      'md link "./no-such-dir/" in docs/cli.md: trailing slash, but "docs/no-such-dir" is not a repo directory',
    ],
    [
      "./cli.md/",
      "docs/operations.md",
      'md link "./cli.md/" in docs/operations.md: trailing slash, but "docs/cli.md" is not a repo directory',
    ],
  ])("%s from %s fails the build", (href, source, message) => {
    expect(() => rewriteMdHref(href, from(source), "/cb/")).toThrow(message);
  });
});
