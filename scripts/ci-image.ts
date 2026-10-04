#!/usr/bin/env bun

// The CI image's coordinates for the workflows, from one derivation of its name. Each mode writes step
// outputs (GITHUB_OUTPUT) and nothing else.
//
//   digest       checks.yml image job: CI_IMAGE_TAG resolved to the digest every Linux job pins   -> container
//   coordinates  container-image.yml: the image name, the content tag, the proto build arg         -> name, tag, proto
//   latest       container-image.yml: whether this commit may move the :latest tag                 -> publish

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { $ } from "bun";
import { die, githubOutput, repoRoot, requiredEnv, selectMode } from "./lib.ts";
import { readPin } from "./pin.ts";

/** GHCR coordinates are lowercase; `github.repository` keeps the owner's and the repository's own case. */
export function imageName(repository: string): string {
  return `ghcr.io/${repository.toLowerCase()}-ci`;
}

/**
 * Everything the image is built from: the Containerfile, .dockerignore, and the files .dockerignore lets
 * into the build context. The .dockerignore is the one owner of that list; the workflow's `paths` trigger
 * is a copy of it (ci-image.test.ts holds the two together).
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

/**
 * The content tag: a digest over each input's name and digest, so bytes moving across file boundaries
 * change it as surely as an edit does.
 */
export function contentTag(root: string, inputs: readonly string[]): string {
  const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
  const manifest = inputs.map((path) => `${sha256(readFileSync(join(root, path)))}  ${path}\n`);
  return sha256(manifest.join("")).slice(0, 12);
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

const modes: Record<string, () => Promise<void>> = {
  async digest() {
    const tag = process.env.CI_IMAGE_TAG ?? "";
    if (tag === "") return;
    const reference = `${imageName(requiredEnv("GITHUB_REPOSITORY"))}:${tag}`;
    // Interpolated, so the shell neither brace-expands nor splits the Go template.
    const format = "{{.Manifest.Digest}}";
    const inspect =
      await $`docker buildx imagetools inspect ${reference} --format ${format}`.nothrow();
    if (inspect.exitCode !== 0) die(`imagetools inspect ${reference} failed:\n${inspect.stderr}`);
    githubOutput("container", containerRecord(reference, inspect.text()));
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
