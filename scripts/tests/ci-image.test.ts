import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  containerRecord,
  contentTag,
  imageInputs,
  imageName,
  latestDecision,
} from "../ci-image.ts";
import { repoRoot, Scratch, writeTree } from "../lib.ts";

const scratch = new Scratch();
afterAll(() => scratch.remove());

function context(admitted: Record<string, string>): string {
  const root = scratch.dir("ci-image-context");
  writeTree(root, {
    Containerfile: "FROM example.com/base@sha256:0000\n",
    ".dockerignore": `*\n${Object.keys(admitted)
      .map((path) => `!${path}\n`)
      .join("")}`,
    ...admitted,
  });
  return root;
}

// GHCR refuses an upper-case coordinate, and GitHub hands the repository name over in the owner's case.
test("the image name is the lower-cased repository under ghcr.io with the -ci suffix", () => {
  expect(imageName("Example-User/Some-Repo")).toBe("ghcr.io/example-user/some-repo-ci");
});

// What would drift silently: the build-input list, which the workflow's `paths` trigger copies and no
// tool compares. The tag's framing claim (bytes moving between files change it) is a property of this
// code, not of sha256, so it is pinned on hand-written contents.
describe("image inputs and the content tag", () => {
  test("an admitted glob is refused: the tag can only hash named files", () => {
    const root = context({ "scripts/*.sh": "" });
    expect(() => imageInputs(root)).toThrow(/pattern, not a file: !scripts\/\*\.sh/);
  });

  test("equal contents give equal tags, and the same bytes split differently across files do not", () => {
    const same = [context({ a: "ab", b: "cd" }), context({ a: "ab", b: "cd" })];
    const moved = context({ a: "abc", b: "d" });
    const tags = [...same, moved].map((root) => contentTag(root, imageInputs(root)));
    expect(tags.map((tag) => /^[0-9a-f]{12}$/.test(tag))).toEqual([true, true, true]);
    expect(tags[0]).toBe(tags[1] as string);
    expect(tags[2]).not.toBe(tags[0] as string);
  });

  test("container-image.yml's paths trigger names exactly the inputs plus the workflow itself", () => {
    const workflow = ".github/workflows/container-image.yml";
    const parsed = Bun.YAML.parse(readFileSync(join(repoRoot, workflow), "utf8")) as {
      on: { push: { paths: string[] } };
    };
    expect([...parsed.on.push.paths].sort()).toEqual([...imageInputs(repoRoot), workflow].sort());
  });
});

// `imagetools inspect --format` exits 0 with whatever the template yields; the Linux jobs would then pin
// `image@` and fail one by one instead of here.
describe("containerRecord", () => {
  const reference = "ghcr.io/example-user/repo-ci:latest";
  const digest = `sha256:${"ab".repeat(32)}`;

  test("a digest becomes the container record the jobs read with fromJSON, pinned by digest", () => {
    expect(JSON.parse(containerRecord(reference, `${digest}\n`))).toEqual({
      image: `ghcr.io/example-user/repo-ci@${digest}`,
      options: "--user root",
    });
  });

  test.each([
    ["an empty template result", ""],
    ["a truncated digest", "sha256:abcdef"],
    ["an error printed on stdout", "ERROR: manifest unknown"],
    ["two digests", `${digest}\n${digest}\n`],
  ])("%s is refused, quoting what was printed", (_name, printed) => {
    expect(() => containerRecord(reference, printed)).toThrow(
      `could not resolve ${reference} to a digest (got ${JSON.stringify(printed)})`,
    );
  });
});

// The rule the workflow comment states and nothing enforces: a rerun or a late finish of an older main
// commit must not move `latest` backward.
describe("latestDecision", () => {
  const head = "a".repeat(40);
  const older = "b".repeat(40);
  test.each<[string, string, string, ReturnType<typeof latestDecision>]>([
    ["the head of main, built from main, publishes", "refs/heads/main", head, { publish: true }],
    [
      "a main commit no longer at the head does not",
      "refs/heads/main",
      older,
      { publish: false, notice: `${older} is no longer the head of main (${head})` },
    ],
    [
      "a dispatch from another ref does not, even at main's head commit",
      "refs/heads/topic",
      head,
      { publish: false, notice: "refs/heads/topic is not main" },
    ],
  ])("%s", (_name, ref, sha, decision) => {
    expect(latestDecision(ref, sha, head)).toEqual(decision);
  });
});
