import { afterAll, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  classifyInspection,
  containerRecord,
  contentTag,
  type ImageRun,
  imageInputs,
  imageName,
  imageRun,
  imageSelection,
  imageWorkflow,
  latestDecision,
  triggerPaths,
} from "../ci-image.ts";
import { repoRoot, runGit, Scratch, writeTree } from "../lib.ts";

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

  test("container-image.yml's push and pull_request triggers each name exactly the trigger paths", () => {
    const parsed = Bun.YAML.parse(readFileSync(join(repoRoot, imageWorkflow), "utf8")) as {
      on: { push: { paths: string[] }; pull_request: { paths: string[] } };
    };
    const expected = [...triggerPaths(repoRoot)].sort();
    expect([...parsed.on.push.paths].sort()).toEqual(expected);
    expect([...parsed.on.pull_request.paths].sort()).toEqual(expected);
  });
});

// Two facts the source does not say. A same-repository pull request that changes an input waits for its
// own build: the checks once ran on main's image and could not prove a Containerfile fix, nor fix a red
// one. A fork's pull request never waits: GitHub hands it a read-only token, so no build of its content
// ever publishes, and a wait would spend the job's timeout.
describe("imageSelection", () => {
  const content = "0123456789ab";
  const changing: ImageRun = { event: "pull_request", sameRepository: true, changesTrigger: true };
  test.each<[string, boolean, { tag: string; wait: boolean }]>([
    [
      "a same-repository pull request waits for the tag it is building",
      true,
      { tag: content, wait: true },
    ],
    ["a fork's pull request falls back at once, saying why", false, { tag: "latest", wait: false }],
  ])("%s", (_name, sameRepository, decision) => {
    const selection = imageSelection(content, "latest", false, { ...changing, sameRepository });
    expect(selection).toMatchObject(decision);
    if (decision.wait) expect(selection.notice).toBeUndefined();
    else expect(selection.notice).toContain(content);
  });
});

// The external fact: docker's wording for a tag the registry does not hold. Any other failure read as
// absence would run the jobs on the fallback while the content image exists.
describe("classifyInspection", () => {
  const reference = "ghcr.io/example-user/repo-ci:0123456789ab";
  const digest = `sha256:${"cd".repeat(32)}\n`;
  const token =
    "ERROR: failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Aexample-user%2Frepo-ci%3Apull&service=ghcr.io: 404 Not Found";
  const dns = "ERROR: failed to do request: dial tcp: lookup ghcr.io: no such host";
  test.each<[string, number, string, string, ReturnType<typeof classifyInspection>]>([
    ["exit 0 is the digest printed", 0, digest, "", { kind: "digest", digest }],
    [
      "docker's not-found diagnostic for the reference is absence",
      1,
      "",
      `ERROR: ${reference}: not found\n`,
      { kind: "absent", said: `ERROR: ${reference}: not found` },
    ],
    [
      "a token endpoint's 404 Not Found is a failure to ask",
      1,
      "",
      `${token}\n`,
      { kind: "failed", said: token },
    ],
    ["any other failure is a failure to ask", 1, "", `${dns}\n`, { kind: "failed", said: dns }],
  ])("%s", (_name, exitCode, stdout, stderr, inspected) => {
    expect(classifyInspection(reference, exitCode, stdout, stderr)).toEqual(inspected);
  });
});

// What would drift silently: the diff is over the trigger paths alone, so a pull request touching only
// sources never waits for an image nobody builds.
describe("imageRun", () => {
  const env = (base: string, head: string) => ({
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_REPOSITORY: "example-user/repo",
    PR_HEAD_REPOSITORY: "example-user/repo",
    PR_BASE_SHA: base,
    PR_HEAD_SHA: head,
    PATH: process.env.PATH,
  });

  function commit(git: (...args: string[]) => string, message: string): void {
    git("add", ".");
    git("commit", "-q", "--allow-empty", "-m", message);
  }

  /** A base commit, then `change` committed on top as the pull request's head; the identity is the scratch repository's own. */
  function repository(change: Record<string, string>): {
    root: string;
    base: string;
    head: string;
    git: (...args: string[]) => string;
  } {
    const root = context({ ".prototools": 'proto = "1.0.0"\n' });
    writeTree(root, { "src/main.rs": "fn main() {}\n" });
    const git = (...args: string[]) => runGit(root, { PATH: process.env.PATH }, ...args);
    git("init", "-q", "-b", "main");
    git("config", "user.name", "t");
    git("config", "user.email", "t@example.invalid");
    commit(git, "base");
    const base = git("rev-parse", "HEAD").trim();
    writeTree(root, change);
    commit(git, "change");
    const head = git("rev-parse", "HEAD").trim();
    return { root, base, head, git };
  }

  test("a pull request changing an admitted file changes the trigger; one changing a source does not", () => {
    const input = repository({ ".prototools": 'proto = "1.0.1"\n' });
    const source = repository({ "src/main.rs": "fn main() { }\n" });
    expect(imageRun(env(input.base, input.head), input.root).changesTrigger).toBe(true);
    expect(imageRun(env(source.base, source.head), source.root).changesTrigger).toBe(false);
  });

  // GitHub's paths filter reads the pull request's own commits (merge-base to head), so the publisher
  // builds for this pull request; a diff of the merge checkout against the base would read nothing
  // changed and pin the fallback while the publisher's tag is on its way.
  test("a pull request whose input change main made too in the meantime still changes the trigger", () => {
    const { root, base, head, git } = repository({ ".prototools": 'proto = "1.0.1"\n' });
    git("checkout", "-q", base);
    writeTree(root, { ".prototools": 'proto = "1.0.1"\n' });
    commit(git, "the same change on main");
    const main = git("rev-parse", "HEAD").trim();
    git("merge", "-q", "--no-ff", "-m", "merge", head);
    expect(git("diff", "--name-only", main, "HEAD").trim()).toBe("");
    expect(imageRun(env(main, head), root).changesTrigger).toBe(true);
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
