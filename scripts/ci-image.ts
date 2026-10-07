#!/usr/bin/env bun

// The CI image's coordinates for the workflows, from one derivation of its name. Each mode writes step
// outputs (GITHUB_OUTPUT) and nothing else.
//
//   digest       checks.yml image job: the image every Linux job pins, by digest (imageSelection)  -> container
//   coordinates  container-image.yml: the image name, the content tag, the proto build arg        -> name, tag, proto
//   latest       container-image.yml: whether this commit may move the :latest tag                -> publish

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { $ } from "bun";
import pWaitFor from "p-wait-for";
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

/** The workflow that builds and publishes the image, on a push to main and on a pull request alike. */
export const imageWorkflow = ".github/workflows/container-image.yml";

/**
 * Everything the image is built from: the Containerfile, .dockerignore, and the files .dockerignore lets
 * into the build context. The .dockerignore is the one owner of that list; the workflow's `paths`
 * triggers are a copy of it (ci-image.test.ts holds the two together).
 */
export function imageInputs(root: string): string[] {
  const admitted = readFileSync(join(root, ".dockerignore"), "utf8")
    .split("\n")
    .filter((line) => line.startsWith("!"))
    .map((line) => line.slice(1));
  for (const path of admitted) {
    if (/[*?[]/.test(path)) throw new Error(`.dockerignore admits a pattern, not a file: !${path}`);
  }
  return ["Containerfile", ".dockerignore", ...admitted];
}

/** The paths whose change makes container-image.yml build: every input plus the workflow itself. */
export function triggerPaths(root: string): string[] {
  return [...imageInputs(root), imageWorkflow];
}

/**
 * How long the publishing job may run, read from the workflow so the wait for its tag has the same
 * bound: a build still going past it has been stopped, and waiting longer would wait for nothing.
 */
export function publishTimeoutMinutes(root: string): number {
  const parsed = Bun.YAML.parse(readFileSync(join(root, imageWorkflow), "utf8")) as {
    jobs?: { publish?: { "timeout-minutes"?: unknown } };
  };
  const minutes = parsed.jobs?.publish?.["timeout-minutes"];
  if (typeof minutes !== "number") throw new Error(`${imageWorkflow}: no publish timeout-minutes`);
  return minutes;
}

/**
 * The content tag: a digest over each input's name and digest, so bytes moving across file boundaries
 * change it as surely as an edit does.
 */
export function contentTag(root: string, inputs: readonly string[]): string {
  const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
  const manifest = inputs.map((path) => `${sha256(readFileSync(join(root, path)))}  ${path}\n`);
  return sha256(manifest.join("")).slice(0, 12);
}

/** What the image job runs in: the event, and for a pull request, whose head it is and what it changes. */
export interface ImageRun {
  event: string;
  /** The pull request's head is this repository's own, so its token may publish; a fork's is read-only. */
  sameRepository: boolean;
  /** The pull request changes a trigger path, so container-image.yml is building from it on this event. */
  changesTrigger: boolean;
}

/**
 * The run from the step's env: GITHUB_EVENT_NAME, and for a pull request the base sha and head repository
 * checks.yml passes from github.event.pull_request. The diff against the base is the pull request's own
 * change, since the checkout is its merge with the base.
 */
export function imageRun(env: Env, root = repoRoot): ImageRun {
  const event = requiredEnv("GITHUB_EVENT_NAME", env);
  if (event !== "pull_request") return { event, sameRepository: false, changesTrigger: false };
  const base = requiredEnv("PR_BASE_SHA", env);
  const changed = runGit(
    root,
    gitEnv(env),
    "diff",
    "--name-only",
    base,
    "HEAD",
    "--",
    ...triggerPaths(root),
  );
  return {
    event,
    sameRepository:
      requiredEnv("PR_HEAD_REPOSITORY", env) === requiredEnv("GITHUB_REPOSITORY", env),
    changesTrigger: changed.trim() !== "",
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
 * publishes beside these checks), a fork's pull request (it cannot publish), and a checkout whose inputs
 * main never published.
 */
export function imageSelection(
  content: string,
  fallback: string,
  published: boolean,
  run: ImageRun,
): ImageSelection {
  if (published) return { tag: content, wait: false };
  if (run.event === "pull_request" && run.sameRepository && run.changesTrigger) {
    return { tag: content, wait: true };
  }
  const why =
    run.event !== "pull_request"
      ? `a ${run.event} leaves publishing one to ${imageWorkflow}`
      : run.sameRepository
        ? "this pull request changes no build input"
        : "a pull request from a fork cannot publish one";
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
      const minutes = publishTimeoutMinutes(repoRoot);
      console.log(
        `waiting up to ${minutes} minutes for ${reference}, published by this pull request's ${imageWorkflow} run`,
      );
      // A failed ask is retried like absence until the bound.
      digest = await pWaitFor(
        async () => {
          const polled = await inspect(reference);
          return polled.kind === "digest" && pWaitFor.resolveWith(polled.digest);
        },
        {
          interval: 30_000,
          before: false,
          timeout: {
            milliseconds: minutes * 60_000,
            message: new Error(
              `${reference} was not published within ${minutes} minutes: this pull request's ${imageWorkflow} run did not push it (its build failed or was stopped); see that run`,
            ),
          },
        },
      );
    } else {
      const fallen = await inspect(reference);
      if (fallen.kind !== "digest") die(`imagetools inspect ${reference} failed: ${fallen.said}`);
      digest = fallen.digest;
    }
    const container = containerRecord(reference, digest);
    console.log(`CI image: ${reference} is ${(JSON.parse(container) as { image: string }).image}`);
    githubOutput("container", container);
  },
  async coordinates() {
    githubOutput("name", imageName(requiredEnv("GITHUB_REPOSITORY")));
    githubOutput("tag", contentTag(repoRoot, imageInputs(repoRoot)));
    githubOutput("proto", readPin("proto"));
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
