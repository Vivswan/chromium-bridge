import { afterAll, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
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
  materializeContext,
  mergeHeadCheck,
  publishEligibility,
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

  // The publisher hashes and builds a pull request's checkout in a subdirectory of main's; what the tag
  // names must not reach past it. Docker reads `Containerfile.dockerignore` in place of `.dockerignore`
  // when present, which would widen the context without touching a hashed file.
  test.each([
    [
      "an admitted path that climbs out of the root",
      { "../package.json": "" },
      /not a plain path inside the build context: !\.\.\/package\.json/,
    ],
    [
      "an admitted absolute path",
      { "/etc/passwd": "" },
      /not a plain path inside the build context: !\/etc\/passwd/,
    ],
    [
      "a Containerfile.dockerignore beside the .dockerignore",
      { "Containerfile.dockerignore": "*\n" },
      /Containerfile\.dockerignore would replace \.dockerignore/,
    ],
  ])("%s is refused", (_name, admitted, message) => {
    const root = context(admitted as Record<string, string>);
    expect(() => imageInputs(root)).toThrow(message);
  });

  test("a symlinked input is refused: the tag hashes the checkout's own bytes", () => {
    const root = context({});
    writeTree(root, { "outside/.prototools": 'proto = "9.9.9"\n' });
    symlinkSync(join(root, "outside/.prototools"), join(root, ".prototools"));
    writeFileSync(join(root, ".dockerignore"), "*\n!.prototools\n");
    expect(() => contentTag(root, imageInputs(root))).toThrow(/\.prototools is a symlink/);
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

// The one predicate both image workflows and the image job apply. The fork row is the fact GitHub
// enforces and nothing here states: a fork's token is read-only, so no build of its content ever
// publishes, and a wait for one would spend the job's timeout. The dependabot row says the actor is not
// an input: no step a pull request controls holds a token, so there is nothing to withhold from it.
describe("publishEligibility", () => {
  const repository = "example-user/repo";
  test.each<[string, string, string, ReturnType<typeof publishEligibility>]>([
    [
      "a push is not a pull request",
      "push",
      "",
      { eligible: false, reason: "a push is not a pull request" },
    ],
    [
      "a pull request from this repository is eligible",
      "pull_request",
      repository,
      { eligible: true },
    ],
    [
      "a fork's pull request is not",
      "pull_request",
      "fork-owner/repo",
      { eligible: false, reason: `a pull request from fork-owner/repo is not ${repository}'s own` },
    ],
    [
      "a dependabot pull request from this repository is an ordinary one",
      "pull_request",
      repository,
      { eligible: true },
    ],
  ])("%s", (_name, event, headRepository, eligibility) => {
    expect(publishEligibility(event, headRepository, repository)).toEqual(eligibility);
  });
});

// The fact the first incident taught: a same-repository pull request that changes an input waits for its
// own build (the checks once ran on main's image and could not prove a Containerfile fix, nor fix a red
// one), and anything ineligible falls back at once.
describe("imageSelection", () => {
  const content = "0123456789ab";
  const changing: ImageRun = { eligibility: { eligible: true }, changesTrigger: true };
  test.each<[string, ImageRun, { tag: string; wait: boolean }]>([
    [
      "an eligible pull request waits for the tag it is building",
      changing,
      { tag: content, wait: true },
    ],
    [
      "an ineligible run falls back at once, saying why",
      { ...changing, eligibility: { eligible: false, reason: "a fork" } },
      { tag: "latest", wait: false },
    ],
  ])("%s", (_name, run, decision) => {
    const selection = imageSelection(content, "latest", false, run);
    expect(selection).toMatchObject(decision);
    if (decision.wait) expect(selection.notice).toBeUndefined();
    else expect(selection.notice).toContain(content);
  });
});

// What the build can copy is what the tag hashes: the context is written from the commit's blobs, never
// the checkout's files, so a symlink (a blob of mode 120000) or a path under a symlinked directory (not
// in the tree at all) is refused instead of read through.
describe("materializeContext", () => {
  const env = { PATH: process.env.PATH };
  function committed(files: Record<string, string>, links: Record<string, string>): string {
    const root = scratch.dir("ci-image-commit");
    writeTree(root, { Containerfile: "FROM scratch\n", ...files });
    for (const [path, target] of Object.entries(links)) symlinkSync(target, join(root, path));
    const git = (...args: string[]) => runGit(root, env, ...args);
    git("init", "-q", "-b", "main");
    git("config", "user.name", "t");
    git("config", "user.email", "t@example.invalid");
    git("add", ".");
    git("commit", "-q", "-m", "inputs");
    return root;
  }

  test("exactly the admitted blobs are written, a leading space before a bang included, and nothing else", () => {
    const root = committed(
      {
        ".dockerignore": "*\n!.prototools\n !pins/extra\n",
        ".prototools": "p",
        "pins/extra": "e",
        "src/main.rs": "",
      },
      {},
    );
    const out = scratch.dir("ci-image-context");
    expect(materializeContext(root, out, env).sort()).toEqual(
      [".dockerignore", "Containerfile", ".prototools", "pins/extra"].sort(),
    );
    expect(readdirSync(out, { recursive: true }).sort()).toEqual(
      [".dockerignore", "Containerfile", ".prototools", "pins", "pins/extra"].sort(),
    );
    expect(readFileSync(join(out, "pins/extra"), "utf8")).toBe("e");
  });

  test("a symlinked input is refused by its mode", () => {
    const root = committed(
      { ".dockerignore": "*\n!.prototools\n" },
      { ".prototools": "../outside" },
    );
    expect(() => materializeContext(root, scratch.dir("ci-image-context"), env)).toThrow(
      ".prototools is not a regular file in the commit (mode 120000)",
    );
  });

  test("an input under a symlinked directory is refused as not in the commit", () => {
    const root = committed({ ".dockerignore": "*\n!inputs/.prototools\n" }, { inputs: ".." });
    expect(() => materializeContext(root, scratch.dir("ci-image-context"), env)).toThrow(
      "inputs/.prototools is not in the commit",
    );
  });
});

// The publisher must build the merge commit the triggering run was about; a newer push moves the merge
// ref under a run still in flight, and publishing from it would tag content that run never built.
describe("mergeHeadCheck", () => {
  const head = "a".repeat(40);
  const newer = "b".repeat(40);
  test("a merge of the run's head passes", () => {
    expect(mergeHeadCheck("refs/pull/7/merge", head, head)).toEqual({ ok: true });
  });
  test("a merge of a newer head is refused, naming both shas", () => {
    expect(mergeHeadCheck("refs/pull/7/merge", newer, head)).toEqual({
      ok: false,
      refused: `refs/pull/7/merge merges ${newer}, not this run's head ${head}: nothing published (the pull request moved on; its newer run publishes)`,
    });
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
