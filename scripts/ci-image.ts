#!/usr/bin/env bun

// The CI image's coordinates for the workflows, from one derivation of its name. Each mode writes step
// outputs (GITHUB_OUTPUT) and nothing else.
//
//   digest          checks.yml image job: the image every Linux job pins, by digest (imageSelection), its
//                   provenance verified                                                                 -> container
//   eligible        both image workflows: whether this run is a pull request this repository builds for -> eligible
//   merge-checkout  container-image-publish.yml: the pull request's merge commit into CI_IMAGE_ROOT, refused
//                   unless it merges the run's head, then its build context into CI_IMAGE_CONTEXT       -> (dies)
//   context         container-image.yml: this checkout's build context into CI_IMAGE_CONTEXT             -> (dies)
//   coordinates     both image workflows: the image name, the content tag, the platform, the proto build
//                   arg, read from CI_IMAGE_ROOT (default: this checkout)                                -> name, tag, platform, proto
//   unpublished     container-image-publish.yml: whether the content tag is still free to push            -> publish
//   push            container-image-publish.yml: docker push of the content tag; the digest it reported -> digest
//   latest          container-image.yml: whether this commit may move the :latest tag                    -> publish

import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { $ } from "bun";
import pWaitFor, { TimeoutError } from "p-wait-for";
import {
  die,
  type Env,
  gitEnv,
  githubOutput,
  repoRoot,
  requiredEnv,
  runGit,
  selectMode,
} from "./lib.ts";
import { readPin } from "./pin.ts";

/** GHCR coordinates are lowercase; `github.repository` keeps the owner's and the repository's own case. */
export function imageName(repository: string): string {
  return `ghcr.io/${repository.toLowerCase()}-ci`;
}

/** The workflow that builds the image: pushed from main, built without pushing on a pull request. */
export const imageWorkflow = ".github/workflows/container-image.yml";
/** The workflow that publishes a pull request's image, running main's own definition after the build above. */
export const publishWorkflow = ".github/workflows/container-image-publish.yml";

/**
 * The platform the image is built for, part of the content tag. Every build step takes it from the
 * coordinates output and passes exactly the Containerfile's default-less ARGs, each from the output of
 * the pin it names (ci-image.test.ts holds every build step to both).
 */
export const imagePlatform = "linux/amd64";

/** The workflows whose provenance attestation the image job accepts, as `gh attestation verify --signer-workflow` names them. */
export function signerWorkflows(repository: string): string[] {
  return [imageWorkflow, publishWorkflow].map((workflow) => `${repository}/${workflow}`);
}

/**
 * Everything the image is built from: the Containerfile, .dockerignore, and the files .dockerignore lets
 * into the build context. The .dockerignore is the one owner of that list; the workflow's `paths`
 * triggers are a copy of it (ci-image.test.ts holds the two together).
 */
export function imageInputs(root: string): string[] {
  // Docker reads it in place of .dockerignore when present: the context would widen with no hashed
  // file touched.
  if (existsSync(join(root, "Containerfile.dockerignore"))) {
    throw new Error(
      "Containerfile.dockerignore would replace .dockerignore as the context's owner",
    );
  }
  // Trimmed as docker trims, so the list read here is the list docker applies.
  const admitted = readFileSync(join(root, ".dockerignore"), "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("!"))
    .map((line) => line.slice(1));
  for (const path of admitted) {
    if (/[*?[]/.test(path)) throw new Error(`.dockerignore admits a pattern, not a file: !${path}`);
    // The publisher hashes a pull request's checkout inside main's; a path may not reach past it.
    if (isAbsolute(path) || path.split("/").some((part) => part === "..")) {
      throw new Error(
        `.dockerignore admits a path that is not a plain path inside the build context: !${path}`,
      );
    }
  }
  return ["Containerfile", ".dockerignore", ...admitted];
}

/** The paths whose change makes container-image.yml build: every input plus the workflow itself. */
export function triggerPaths(root: string): string[] {
  return [...imageInputs(root), imageWorkflow];
}

/** A job's `timeout-minutes`, read from its workflow. */
function jobTimeoutMinutes(root: string, workflow: string, job: string): number {
  const parsed = Bun.YAML.parse(readFileSync(join(root, workflow), "utf8")) as {
    jobs?: Record<string, { "timeout-minutes"?: unknown }>;
  };
  const minutes = parsed.jobs?.[job]?.["timeout-minutes"];
  if (typeof minutes !== "number") throw new Error(`${workflow}: no ${job} timeout-minutes`);
  return minutes;
}

/**
 * How long a pull request's tag may take to appear: its build job, then the publishing job that runs
 * after it, each as long as its workflow allows. A build still going past that has been stopped, and
 * waiting longer would wait for nothing.
 */
export function publishBoundMinutes(root: string): number {
  return (
    jobTimeoutMinutes(root, imageWorkflow, "build") +
    jobTimeoutMinutes(root, publishWorkflow, "publish")
  );
}

/**
 * The build context the publishers hand docker: exactly the inputs, written under `out` from the blobs
 * of the commit checked out at `root`, so a Containerfile can copy nothing the tag does not hash. A
 * path that is not a regular file in the commit (a symlink, a directory, a submodule, or absent, as a
 * path under a symlinked directory is) is refused by name, so no byte outside the commit is read.
 */
export function materializeContext(root: string, out: string, env: Env): string[] {
  const blob = (path: string): void => {
    const entry = runGit(root, env, "ls-tree", "HEAD", "--", path).trim();
    if (entry === "") throw new Error(`${path} is not in the commit`);
    const mode = entry.split(" ")[0];
    if (mode !== "100644" && mode !== "100755") {
      throw new Error(`${path} is not a regular file in the commit (mode ${mode})`);
    }
    const show = Bun.spawnSync(["git", "show", `HEAD:${path}`], {
      cwd: root,
      env,
      stdout: "pipe",
      stderr: "pipe",
    });
    if (show.exitCode !== 0)
      throw new Error(`git show HEAD:${path} failed: ${show.stderr.toString().trim()}`);
    mkdirSync(dirname(join(out, path)), { recursive: true });
    writeFileSync(join(out, path), show.stdout);
  };
  blob(".dockerignore");
  blob("Containerfile");
  const inputs = imageInputs(out);
  for (const path of inputs) if (path !== ".dockerignore" && path !== "Containerfile") blob(path);
  return inputs;
}

/**
 * The content tag: a digest over each input's name and digest, so bytes moving across file boundaries
 * change it as surely as an edit does, and over the platform the image is built for.
 */
export function contentTag(root: string, inputs: readonly string[]): string {
  const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
  const manifest = inputs.map((path) => {
    // The checkout's own bytes: a link would hash, and build from, a file the tag does not name.
    if (lstatSync(join(root, path)).isSymbolicLink()) throw new Error(`${path} is a symlink`);
    return `${sha256(readFileSync(join(root, path)))}  ${path}\n`;
  });
  manifest.push(`platform ${imagePlatform}\n`);
  return sha256(manifest.join("")).slice(0, 12);
}

/** Whether a run is a pull request this repository builds an image for. */
export type Eligibility = { eligible: true } | { eligible: false; reason: string };

/**
 * The one predicate both image workflows and the image job apply: a pull request whose head is this
 * repository's own. A fork's is not. The actor does not enter: no step a pull request controls holds a
 * token (its build job pushes nothing, and the publisher runs main's own definition), so a dependabot
 * pull request is an ordinary one.
 */
export function publishEligibility(
  event: string,
  headRepository: string,
  repository: string,
): Eligibility {
  if (event !== "pull_request")
    return { eligible: false, reason: `a ${event} is not a pull request` };
  if (headRepository !== repository) {
    return {
      eligible: false,
      reason: `a pull request from ${headRepository} is not ${repository}'s own`,
    };
  }
  return { eligible: true };
}

/** What the image job runs in: whether this repository builds for it, and whether it changes a trigger path. */
export interface ImageRun {
  eligibility: Eligibility;
  /** The pull request changes a trigger path, so container-image.yml is building from it on this event. */
  changesTrigger: boolean;
}

/**
 * The run from the step's env: GITHUB_EVENT_NAME, and for a pull request the base and head shas and the
 * head repository checks.yml passes from github.event.pull_request. The diff is the pull request's own
 * commits (merge base to head), the same files GitHub's `paths` filter reads to start the build, so the
 * two agree even when main changed a trigger path in the meantime. The content tag is the merge
 * checkout's, as in the publisher.
 */
export function imageRun(env: Env, root = repoRoot): ImageRun {
  const event = requiredEnv("GITHUB_EVENT_NAME", env);
  if (event !== "pull_request") {
    return { eligibility: publishEligibility(event, "", ""), changesTrigger: false };
  }
  const eligibility = publishEligibility(
    event,
    requiredEnv("PR_HEAD_REPOSITORY", env),
    requiredEnv("GITHUB_REPOSITORY", env),
  );
  const range = `${requiredEnv("PR_BASE_SHA", env)}...${requiredEnv("PR_HEAD_SHA", env)}`;
  const changed = runGit(
    root,
    gitEnv(env),
    "diff",
    "--name-only",
    range,
    "--",
    ...triggerPaths(root),
  );
  return { eligibility, changesTrigger: changed.trim() !== "" };
}

/**
 * The publisher builds the pull request's merge commit, the one checks.yml's jobs run and hash, and only
 * the one the triggering run was about: a merge ref that no longer merges that run's head belongs to a
 * newer push, whose own run publishes.
 */
export function mergeHeadCheck(
  mergeRef: string,
  secondParent: string,
  headSha: string,
): { ok: true } | { ok: false; refused: string } {
  if (secondParent === headSha) return { ok: true };
  return {
    ok: false,
    refused: `${mergeRef} merges ${secondParent}, not this run's head ${headSha}: nothing published (the pull request moved on; its newer run publishes)`,
  };
}

export interface ImageSelection {
  tag: string;
  /** The tag is not in the registry yet: this event's container-image.yml run publishes it. */
  wait: boolean;
  /** Why the run falls back to the tag main last published. */
  notice?: string;
}

/**
 * The image the Linux jobs run: the one built from exactly this checkout's inputs when the registry holds
 * it; the one a same-repository pull request is building when it changes a trigger path, waited for; else
 * `fallback`, the tag main last published. The fallback covers a push to main (container-image.yml
 * publishes beside these checks), a fork's pull request (nothing builds for it), and a checkout whose
 * inputs main never published.
 */
export function imageSelection(
  content: string,
  fallback: string,
  published: boolean,
  run: ImageRun,
): ImageSelection {
  if (published) return { tag: content, wait: false };
  if (run.eligibility.eligible && run.changesTrigger) return { tag: content, wait: true };
  const why = run.eligibility.eligible
    ? "this pull request changes no build input"
    : `${run.eligibility.reason}, and only a pull request's build is waited for`;
  return {
    tag: fallback,
    wait: false,
    notice: `running on :${fallback}: no image for build inputs ${content}, and ${why}`,
  };
}

/**
 * The `container` output the Linux jobs read with fromJSON: the image pinned by digest, run as root
 * because the image's own user cannot write the runner-owned workspace. `imagetools inspect --format`
 * prints whatever the template yields, an empty string included, so only a digest shape is accepted.
 */
export function containerRecord(reference: string, inspected: string): string {
  const digest = inspected.trim();
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
    throw new Error(
      `could not resolve ${reference} to a digest (got ${JSON.stringify(inspected)})`,
    );
  }
  const image = reference.slice(0, reference.lastIndexOf(":"));
  return JSON.stringify({ image: `${image}@${digest}`, options: "--user root" });
}

/** `latest` never moves backward: only the current head of main, built from main, may publish it. */
export function latestDecision(
  ref: string,
  sha: string,
  mainHead: string,
): { publish: true } | { publish: false; notice: string } {
  if (ref !== "refs/heads/main") return { publish: false, notice: `${ref} is not main` };
  if (sha !== mainHead) {
    return { publish: false, notice: `${sha} is no longer the head of main (${mainHead})` };
  }
  return { publish: true };
}

/** What `imagetools inspect` said of a reference: its digest, that the registry holds no such tag, or a failure to ask. */
export type Inspected =
  | { kind: "digest"; digest: string }
  | { kind: "absent"; said: string }
  | { kind: "failed"; said: string };

/**
 * docker reports a tag the registry does not hold as `<reference>: not found`, the whole diagnostic;
 * anything else it fails with (the registry unreachable, a token endpoint answering 404 Not Found, a
 * refused login) is not absence, and a selection made on it would run the jobs on the fallback while the
 * content image exists.
 */
export function classifyInspection(
  reference: string,
  exitCode: number,
  stdout: string,
  stderr: string,
): Inspected {
  if (exitCode === 0) return { kind: "digest", digest: stdout };
  const said = stderr.trim();
  return said.endsWith(`${reference}: not found`)
    ? { kind: "absent", said }
    : { kind: "failed", said };
}

/** One ask of the registry, killed after a minute so a stalled ask ends as a failure, not as a hang. */
async function inspect(reference: string): Promise<Inspected> {
  const argv = [
    "docker",
    "buildx",
    "imagetools",
    "inspect",
    reference,
    "--format",
    "{{.Manifest.Digest}}",
  ];
  const run = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe", timeout: 60_000 });
  const [stdout, stderr] = await Promise.all([
    new Response(run.stdout).text(),
    new Response(run.stderr).text(),
  ]);
  const exitCode = await run.exited;
  const said = run.signalCode ? `${stderr}\nkilled by ${run.signalCode} after a minute` : stderr;
  const inspected = classifyInspection(reference, exitCode, stdout, said);
  if (inspected.kind !== "digest") console.log(`${reference}: ${inspected.said}`);
  return inspected;
}

/** `docker push` ends with `<tag>: digest: sha256:<hex> size: <n>`: the manifest digest it pushed, bound to this push alone. */
export function pushedDigest(output: string): string | undefined {
  return /\bdigest: (sha256:[0-9a-f]{64}) size: \d+/.exec(output)?.[1];
}

/** One `gh attestation verify` of the subject against one trusted signer: its output, or what it refused. */
async function attestationBy(
  subject: string,
  repository: string,
  signer: string,
): Promise<{ ok: true; said: string } | { ok: false; said: string }> {
  const argv = [
    "gh",
    "attestation",
    "verify",
    subject,
    "--repo",
    repository,
    "--signer-workflow",
    signer,
    "--source-ref",
    "refs/heads/main",
  ];
  const run = Bun.spawn(argv, { stdout: "pipe", stderr: "pipe", timeout: 120_000 });
  const [stdout, stderr] = await Promise.all([
    new Response(run.stdout).text(),
    new Response(run.stderr).text(),
  ]);
  const ok = (await run.exited) === 0;
  return { ok, said: (ok ? stdout : stderr || stdout).trim() };
}

/**
 * The digest's provenance: an attestation signed by one of this repository's two trusted workflows on
 * main, checked with `gh attestation verify`. Anything a pull request's own YAML pushed carries no such
 * signature, whatever tag it took, so a missing or foreign signer stops the job; it never falls back.
 * The publishers attest right after they push, so a digest seen first is given the bound below (plus
 * the asks in flight at it) to acquire its attestation before the refusal.
 */
async function verifyProvenance(image: string, digest: string, repository: string): Promise<void> {
  const subject = `oci://${image}@${digest}`;
  const signers = signerWorkflows(repository);
  let refusals: string[] = [];
  const minutes = 10;
  try {
    const signed = await pWaitFor(
      async () => {
        refusals = [];
        for (const signer of signers) {
          const verified = await attestationBy(subject, repository, signer);
          if (verified.ok) return pWaitFor.resolveWith(`${signer}\n${verified.said}`);
          refusals.push(`${signer}: ${verified.said}`);
        }
        console.log(`${subject}: no accepted attestation yet, asking again`);
        return false;
      },
      { interval: 30_000, timeout: minutes * 60_000 },
    );
    console.log(`${subject}: provenance signed on main by ${signed}`);
  } catch (error) {
    if (!(error instanceof TimeoutError)) throw error;
    die(
      `${subject} has no provenance attestation from this repository's trusted workflows on main after at least ${minutes} minutes of asking; refusing to run in it.\n${refusals.join("\n")}`,
    );
  }
}

const modes: Record<string, () => Promise<void>> = {
  async digest() {
    const fallback = process.env.CI_IMAGE_TAG ?? "";
    if (fallback === "") return;
    const name = imageName(requiredEnv("GITHUB_REPOSITORY"));
    const content = contentTag(repoRoot, imageInputs(repoRoot));
    const probed = await inspect(`${name}:${content}`);
    if (probed.kind === "failed")
      die(`imagetools inspect ${name}:${content} failed: ${probed.said}`);
    const selection = imageSelection(
      content,
      fallback,
      probed.kind === "digest",
      imageRun(process.env),
    );
    const reference = `${name}:${selection.tag}`;
    if (selection.notice) console.log(`::notice::${selection.notice}`);
    let digest: string;
    if (probed.kind === "digest") {
      digest = probed.digest;
    } else if (selection.wait) {
      const minutes = publishBoundMinutes(repoRoot);
      console.log(
        `waiting up to ${minutes} minutes for ${reference}: this pull request's ${imageWorkflow} run builds it, then ${publishWorkflow} publishes it`,
      );
      // A failed ask is retried like absence until the bound, whose failure quotes the last answer: a
      // persistent refusal reads as itself, not as a build that never published.
      let last = probed.said;
      try {
        digest = await pWaitFor(
          async () => {
            const polled = await inspect(reference);
            if (polled.kind !== "digest") last = polled.said;
            return polled.kind === "digest" && pWaitFor.resolveWith(polled.digest);
          },
          { interval: 30_000, before: false, timeout: minutes * 60_000 },
        );
      } catch (error) {
        if (!(error instanceof TimeoutError)) throw error;
        die(
          `${reference} was not published within ${minutes} minutes: this pull request's ${imageWorkflow} build or its ${publishWorkflow} run did not push it (failed, stopped, or refused; see those runs). The registry's last answer: ${last}`,
        );
      }
    } else {
      const fallen = await inspect(reference);
      if (fallen.kind !== "digest") die(`imagetools inspect ${reference} failed: ${fallen.said}`);
      digest = fallen.digest;
    }
    const container = containerRecord(reference, digest);
    await verifyProvenance(name, digest.trim(), requiredEnv("GITHUB_REPOSITORY"));
    console.log(`CI image: ${reference} is ${(JSON.parse(container) as { image: string }).image}`);
    githubOutput("container", container);
  },
  async eligible() {
    const eligibility = publishEligibility(
      requiredEnv("PUBLISH_EVENT"),
      requiredEnv("PUBLISH_HEAD_REPOSITORY"),
      requiredEnv("GITHUB_REPOSITORY"),
    );
    if (!eligibility.eligible) console.log(`::notice::no image built: ${eligibility.reason}`);
    githubOutput("eligible", String(eligibility.eligible));
  },
  async "merge-checkout"() {
    const number = requiredEnv("PR_NUMBER");
    if (!/^[1-9][0-9]*$/.test(number)) die(`PR_NUMBER is not a pull request number: ${number}`);
    const head = requiredEnv("PR_HEAD_SHA");
    const root = join(repoRoot, requiredEnv("CI_IMAGE_ROOT"));
    const mergeRef = `refs/pull/${number}/merge`;
    const url = `${requiredEnv("GITHUB_SERVER_URL")}/${requiredEnv("GITHUB_REPOSITORY")}`;
    const env = gitEnv(process.env);
    runGit(repoRoot, env, "init", "-q", root);
    runGit(root, env, "fetch", "-q", url, mergeRef);
    runGit(root, env, "checkout", "-q", "FETCH_HEAD");
    const secondParent = runGit(root, env, "rev-parse", "FETCH_HEAD^2").trim();
    const check = mergeHeadCheck(mergeRef, secondParent, head);
    if (!check.ok) die(check.refused);
    console.log(
      `${root}: ${mergeRef} (${runGit(root, env, "rev-parse", "HEAD").trim()}) merges ${head}`,
    );
    const context = join(repoRoot, requiredEnv("CI_IMAGE_CONTEXT"));
    console.log(`${context}: ${materializeContext(root, context, env).join(", ")}`);
  },
  async context() {
    const context = join(repoRoot, requiredEnv("CI_IMAGE_CONTEXT"));
    console.log(
      `${context}: ${materializeContext(repoRoot, context, gitEnv(process.env)).join(", ")}`,
    );
  },
  async coordinates() {
    const root = join(repoRoot, process.env.CI_IMAGE_ROOT ?? ".");
    githubOutput("name", imageName(requiredEnv("GITHUB_REPOSITORY")));
    githubOutput("tag", contentTag(root, imageInputs(root)));
    githubOutput("platform", imagePlatform);
    githubOutput("proto", readPin("proto", root));
  },
  async push() {
    const reference = `${imageName(requiredEnv("GITHUB_REPOSITORY"))}:${requiredEnv("CI_IMAGE_CONTENT_TAG")}`;
    const run = Bun.spawn(["docker", "push", reference], { stdout: "pipe", stderr: "inherit" });
    const output = await new Response(run.stdout).text();
    console.log(output.trimEnd());
    if ((await run.exited) !== 0) die(`docker push ${reference} failed`);
    // The digest of this push, read from its own report: a tag re-read from the registry could by then
    // name an image someone else pushed, and the attestation would sign that one.
    const digest = pushedDigest(output) ?? die(`docker push ${reference} reported no digest`);
    githubOutput("digest", digest);
  },
  async unpublished() {
    const reference = `${imageName(requiredEnv("GITHUB_REPOSITORY"))}:${requiredEnv("CI_IMAGE_CONTENT_TAG")}`;
    const inspected = await inspect(reference);
    if (inspected.kind === "failed")
      die(`imagetools inspect ${reference} failed: ${inspected.said}`);
    if (inspected.kind === "digest") {
      console.log(
        `::notice::${reference} is already published as ${inspected.digest.trim()}: nothing pushed (a content tag never moves)`,
      );
    }
    githubOutput("publish", String(inspected.kind === "absent"));
  },
  async latest() {
    const listed = (await $`git ls-remote origin refs/heads/main`.text()).trim();
    const mainHead = listed.split("\t")[0] ?? "";
    if (!/^[0-9a-f]{40}$/.test(mainHead)) die(`no refs/heads/main on origin (got ${listed})`);
    const decision = latestDecision(requiredEnv("GITHUB_REF"), requiredEnv("GITHUB_SHA"), mainHead);
    if (!decision.publish) console.log(`::notice::latest not moved: ${decision.notice}`);
    githubOutput("publish", String(decision.publish));
  },
};

if (import.meta.main) {
  const run = selectMode(modes, process.argv.slice(2), "scripts/ci-image.ts");
  try {
    await run();
  } catch (error) {
    die((error as Error).message);
  }
}
