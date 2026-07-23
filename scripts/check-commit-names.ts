#!/usr/bin/env bun

// Conventional-commit gate for commit subjects AND the PR title, one source
// of truth for both: CI's commit-names job validates every subject in the
// push/PR range, its conventional-title job validates the PR title (PRs are
// squash-merged, so the title becomes the commit subject and drives
// release-please versioning), and `moon run check-commit-names` validates
// origin/main..HEAD locally. Vendored from Vivswan/repo-platform
// (actions/validate-commit-names), with the type list swapped for
// CONTRIBUTING.md's and the --title mode added; dependency-free on purpose
// (node builtins only) so CI can run it without a bun install.

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

// CONTRIBUTING.md's allowed types - deliberately NOT the generic
// Conventional Commits set: `chore` is banned there (every change maps to a
// more precise type: dependency bumps -> build/ci, misc scripts -> build,
// documentation -> docs).
export const ALLOWED_TYPES = [
  "build",
  "ci",
  "docs",
  "feat",
  "fix",
  "perf",
  "refactor",
  "revert",
  "style",
  "test",
] as const;

// The one carve-out from the chore ban: release-please titles its rolling
// release PR `chore(main): release X.Y.Z`, and that PR flows through this
// same gate when it merges.
const releasePlease = /^chore\(main\): release .+$/;

// The scope charset is deliberately conservative (ASCII word characters plus
// . _ / -), matching CONTRIBUTING.md's examples; widen it only with a
// reviewed edit here.
const conventionalSubject = new RegExp(
  `^(${ALLOWED_TYPES.join("|")})(\\([A-Za-z0-9._/-]+\\))?!?: .+$`,
);

// Unicode Cc = the C0 and C1 control ranges (LF, CR, ESC, ...), plus the
// LINE/PARAGRAPH SEPARATOR characters, which JS regexes treat as line
// terminators but Cc does not cover. None of these can be part of a valid
// one-line subject, and a newline in a PR title echoed to the workflow log
// could inject log commands.
const controlCharacter = /[\p{Cc}\u2028\u2029]/u;

/** Replaces every control character with U+FFFD so hostile text can be
 * echoed to a workflow log without smuggling terminal escapes or extra
 * lines. */
export function sanitizeForLog(value: string): string {
  return value.replace(/[\p{Cc}\u2028\u2029]/gu, "\ufffd");
}

const zeroSha = /^0{40}$/;

interface Commit {
  sha: string;
  subject: string;
}

interface PushPayloadCommit {
  id: string;
  message: string;
}

interface EventPayload {
  // biome-ignore lint/style/useNamingConvention: GitHub's event payload key is snake_case
  pull_request?: { base?: { sha?: string }; head?: { sha?: string } };
  before?: string;
  after?: string;
  commits?: PushPayloadCommit[];
}

/** Returns null when `value` is an acceptable squash-commit subject / PR
 * title, or a human-readable reason it is not. */
export function subjectError(value: string): string | null {
  if (controlCharacter.test(value)) {
    return "contains control characters; use a single plain-text line";
  }
  if (releasePlease.test(value) || conventionalSubject.test(value)) {
    return null;
  }
  return (
    "is not a Conventional Commit with an allowed type " +
    `(${ALLOWED_TYPES.join(" ")}; \`chore\` only as release-please's ` +
    "`chore(main): release ...`)"
  );
}

export function isMergeSubject(value: string): boolean {
  return /^Merge (pull request|branch(es)?|remote-tracking branch|tag|commit)\b/.test(value);
}

function subject(message: unknown): string {
  return (
    String(message ?? "")
      .split(/\r?\n/, 1)[0]
      ?.trim() ?? ""
  );
}

function git(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

// True when `rev` resolves to a commit present in this checkout. A force-push
// orphans the old tip (and a shallow clone may never fetch it), so `before`
// can name a commit that no longer exists -- `git rev-list before..after`
// would then fail fatally. We use this to fall back to the push payload.
function revExists(rev: string): boolean {
  try {
    // stdio "ignore" keeps git's "fatal: Not a valid object name" off the log
    // -- a missing `before` is an expected, handled case, not an error.
    execFileSync("git", ["cat-file", "-e", `${rev}^{commit}`], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Merge commits are excluded structurally (--no-merges, i.e. by parent
// count): their subjects are git-generated, and matching them by text would
// let an ordinary commit named like one slip past validation.
function shasInRange(range: string): string[] {
  const output = git(["rev-list", "--reverse", "--no-merges", range]);
  return output ? output.split(/\r?\n/) : [];
}

function commitSubject(sha: string): string {
  return subject(git(["show", "-s", "--format=%s", sha]));
}

function eventPayload(): EventPayload {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) {
    throw new Error("GITHUB_EVENT_PATH is required.");
  }
  return JSON.parse(readFileSync(eventPath, "utf8")) as EventPayload;
}

function listCommits(): Commit[] {
  const eventName = process.env.GITHUB_EVENT_NAME;

  // Local mode: no GitHub event, so validate what the branch would bring to
  // main - the same range a PR's commit-names job would check.
  if (!eventName) {
    return shasInRange("origin/main..HEAD").map((sha) => ({
      sha,
      subject: commitSubject(sha),
    }));
  }

  if (eventName === "pull_request") {
    const payload = eventPayload();
    const base = payload.pull_request?.base?.sha;
    const head = payload.pull_request?.head?.sha;
    if (!base || !head) {
      throw new Error("pull_request event is missing base/head SHAs.");
    }
    return shasInRange(`${base}..${head}`).map((sha) => ({
      sha,
      subject: commitSubject(sha),
    }));
  }

  if (eventName === "push") {
    const payload = eventPayload();
    const before = payload.before;
    const after = payload.after;
    // Only diff a range when both endpoints are real and reachable here;
    // otherwise (new branch, or a force-push that orphaned `before`) validate
    // the commits GitHub listed in this push payload instead.
    if (before && after && !zeroSha.test(before) && revExists(before) && revExists(after)) {
      return shasInRange(`${before}..${after}`).map((sha) => ({
        sha,
        subject: commitSubject(sha),
      }));
    }
    // Payload commits carry no parent information (the whole point of this
    // fallback is that the range is not resolvable locally), so merge
    // commits are skipped by their git-generated subject here - the only
    // path where the text heuristic still applies.
    return (payload.commits ?? [])
      .map((commit) => ({
        sha: commit.id,
        subject: subject(commit.message),
      }))
      .filter((commit) => !isMergeSubject(commit.subject));
  }

  return [];
}

function validateCommitNames(): void {
  const commits = listCommits();
  const failures = commits
    .map((commit) => ({ commit, error: subjectError(commit.subject) }))
    .filter((failure) => failure.error !== null);

  console.log(`Checked ${commits.length} non-merge commit subject(s).`);

  if (failures.length > 0) {
    // Sanitized: a hostile subject must not be able to write to the log on
    // its own terms (terminal escapes, injected lines).
    const lines = failures.map(
      ({ commit, error }) =>
        `- ${commit.sha.slice(0, 7)} ${sanitizeForLog(commit.subject)}: ${error}`,
    );
    console.error(
      [
        "Commit subjects must be Conventional Commits (see CONTRIBUTING.md).",
        "Examples: `feat: add setup flow`, `fix: repair installer`, `feat!: simplify bootstrap`.",
        "",
        ...lines,
      ].join("\n"),
    );
    process.exitCode = 1;
  }
}

function validateTitle(title: string): void {
  const error = subjectError(title);
  if (error !== null) {
    // The title itself is deliberately not echoed: it is attacker-controlled
    // and may be exactly the kind of string that injects log commands.
    console.error(`The PR title ${error}.`);
    console.error(
      "PRs are squash-merged: the title becomes the commit subject (see CONTRIBUTING.md).",
    );
    process.exitCode = 1;
    return;
  }
  console.log("PR title is a Conventional Commit.");
}

if (import.meta.main) {
  const flag = process.argv.indexOf("--title");
  if (flag !== -1) {
    const title = process.argv[flag + 1];
    if (title === undefined) {
      console.error("usage: check-commit-names.ts [--title <string>]");
      process.exit(2);
    }
    validateTitle(title);
  } else {
    validateCommitNames();
  }
}
