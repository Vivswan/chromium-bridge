import { describe, expect, test } from "bun:test";
import { auditGraph, GATE, type TaskGraph } from "../check-moon-edges";

// Drift answer: moon cannot express "no task runs bunx", "the pre-commit gate runs only the repository's own
// toolchain", or "a task that names a build/ path depends on its writer", and a task added without them fails on
// its first cold run, inside a commit, or against a stale artifact. The graph is hand-written in the shape
// `moon query tasks` returns.
const graph: TaskGraph = {
  root: {
    gate: {
      command: "noop",
      deps: [
        { target: "core:lint" },
        { target: "core:fmt-check" },
        { target: "root:typecheck" },
        { target: "root:hygiene" },
        { target: "root:machete" },
        { target: "root:gen-shared" },
        { target: "root:unfetched" },
        { target: "root:vanished" },
        { target: "root:sneaky-install" },
        { target: "root:sneaky-alias" },
        { target: "root:sneaky-x" },
        { target: "root:sneaky-cwd-x" },
        { target: "root:sneaky-cwd" },
        { target: "root:sneaky-config" },
        { target: "root:frozen-after-dashes" },
        { target: "root:auto-install" },
        { target: "root:logs-to-file" },
        { target: "root:glob-first-word" },
        { target: "root:spaced-background-redirect" },
        { target: "root:escapes-words" },
        { target: "root:overrides-env" },
        { target: "root:negates-a-command" },
        { target: "root:expands-a-word" },
        { target: "root:expands-braces" },
        { target: "root:quotes-braces" },
        { target: "root:launches-inside-the-gate" },
        { target: "root:quotes-ansi-c" },
      ],
    },
    ci: { command: "noop", deps: [{ target: "root:gate" }, { target: "root:check-yaml" }] },
    hygiene: {
      command: "noop",
      deps: [{ target: "root:check-pins" }, { target: "root:check-yaml" }],
    },
    typecheck: {
      command: "set",
      script: "set -e\nbun run tsc -p scripts\nbun run tsc -p src/packages/shared\n",
      deps: [],
    },
    "gen-shared": {
      command: "set",
      script:
        "set -e\nbun scripts/gen-ops.ts\nbun run biome format --write \\\n  src/a.gen.ts \\\n  src/b.gen.ts\n",
      deps: [],
    },
    "check-pins": {
      command: "bun",
      script: "bun test scripts/tests/pin.test.ts && bun scripts/pin.ts",
      deps: [],
    },
    "check-yaml": { command: "uvx", args: ["yamllint@1.38.0", "-s", "."], deps: [] },
    machete: { command: "cargo", args: ["machete"], deps: [], env: { RUSTUP_AUTO_INSTALL: "0" } },
    unfetched: {
      command: "cargo",
      args: ["doc", "--workspace"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "sneaky-cwd": { command: "bun", args: ["--cwd=.", "install"], deps: [] },
    "sneaky-config": { command: "bun", args: ["--config", "install"], deps: [] },
    "frozen-after-dashes": {
      command: "cargo",
      args: ["clippy", "--all-targets", "--", "--frozen"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "auto-install": { command: "cargo", args: ["doc", "--frozen"], deps: [] },
    "sneaky-install": { command: "bun", args: ["install", "--frozen-lockfile"], deps: [] },
    "sneaky-alias": { command: "bun", args: ["i"], deps: [] },
    "sneaky-x": { command: "bun", args: ["x", "fixture-tool"], deps: [] },
    "sneaky-cwd-x": { command: "bun", args: ["--cwd", ".", "x", "fixture-tool"], deps: [] },
    "lint-ts": { command: "bun", args: ["run", "biome", "lint", "."], deps: [] },
    "fmt-ts": {
      command: "bunx",
      args: ["--no-install", "biome", "format", "--write", "."],
      deps: [],
    },
    typos: { command: "typos", deps: [] },
    "build-repro": { command: "bun" },
    setup: {
      command: "set",
      script: "set -e\nbun install --frozen-lockfile\ncargo fetch --locked\n",
      deps: [],
    },
    "build-release": { command: "cargo", args: ["build", "--release"], script: null, deps: [] },
    install: {
      command: "./target/release/chromium-bridge",
      deps: [{ target: "root:build-release" }],
    },
    "quoted-runner": { command: "set", script: 'set -e; "bunx" tsc -p scripts' },
    "reads-built-without-dependency": {
      command: "bun",
      args: ["scripts/check-built.ts"],
      deps: [],
      inputFiles: { "build/extension/chrome-mv3/manifest.json": {} },
    },
    "reads-built-through-aggregate": {
      command: "bun",
      args: ["scripts/pack.ts", "build/extension/chrome-mv3"],
      deps: [{ target: "root:build-all" }],
    },
    "build-all": { command: "noop", deps: [{ target: "extension:build" }] },
    "reads-glob-build": {
      command: "bun",
      args: ["scripts/x.ts"],
      deps: [],
      inputGlobs: { "build/web-pdf/**/*": { cache: true } },
    },
    "writes-and-names-own-output": {
      command: "bun",
      args: ["scripts/zip.ts", "build/bundle"],
      deps: [],
      outputFiles: { "build/bundle": { optional: false } },
    },
    "reads-under-glob-writer": {
      command: "bun",
      args: ["scripts/y.ts"],
      deps: [{ target: "root:writes-glob" }],
      inputFiles: { "build/report-html/index.html": {} },
    },
    "writes-glob": { command: "bun", deps: [], outputGlobs: { "build/report-*/**/*": {} } },
    "names-filesystem-path": {
      command: "bun",
      args: ["scripts/q.ts", "/build/extension"],
      deps: [],
    },
    "reads-dotted-path": {
      command: "bun",
      args: ["scripts/r.ts", "././build/./web/../extension/chrome-mv3/manifest.json"],
      deps: [],
    },
    "mentions-bun": {
      command: "set",
      script: "set -e\n# bun test would be wrong here\necho bun test",
    },
    "comments-build-path": {
      command: "set",
      script: "set -e\nbun scripts/check.ts # build/extension/chrome-mv3/manifest.json\n",
      deps: [],
    },
    "reads-spaced-path": {
      command: "bun",
      script: 'bun scripts/read.ts "build/report html/index.json"',
      deps: [{ target: "root:writes-spaced" }],
    },
    "writes-spaced": { command: "bun", deps: [], outputFiles: { "build/report html": {} } },
    "reads-spaced-path-without-dependency": {
      command: "bun",
      script: 'bun scripts/read.ts "build/report html/index.json"',
      deps: [],
    },
    "reads-redirected-build": {
      command: "bun",
      script: "bun scripts/read.ts < build/extension/result.json",
      deps: [],
    },
    "substitutes-bunx": {
      command: "bun",
      script: "bun scripts/b.ts $(bunx fixture-tool)",
      deps: [],
    },
    "continues-a-word": {
      command: "bu",
      script: "bu\\\nnx fixture-tool\nbun scripts/c.ts \\\n\nbunx other-tool",
      deps: [],
    },
    "unparsable-script": { command: "bun", script: "bun scripts/x.ts ${X", deps: [] },
    "logs-to-file": {
      command: "set",
      script: "set -e\nbun test &> /tmp/test.log\nbun run tsc -p scripts &>> /tmp/test.log",
      deps: [],
    },
    "glob-first-word": { command: "./scripts/*.sh", script: "./scripts/*.sh", deps: [] },
    "spaced-background-redirect": {
      command: "bun",
      script: "bun scripts/a.ts & >out bunx fixture-tool",
      deps: [],
    },
    "reads-glob-word": {
      command: "bun",
      script: "bun scripts/read.ts build/report-glob/*",
      deps: [{ target: "root:writes-report-glob" }],
    },
    "writes-report-glob": { command: "bun", deps: [], outputFiles: { "build/report-glob": {} } },
    "reads-dotted-glob": {
      command: "bun",
      args: ["scripts/x.ts"],
      deps: [],
      inputGlobs: { "./build/web/**/*": { cache: true } },
    },
    "escapes-words": {
      command: "bun",
      script: "bun in\\stall\nb\\unx fixture-tool\nbun scripts/read.ts \\build/escaped/index.json",
      deps: [],
    },
    "escapes-a-backslash-before-a-glob": {
      command: "bun",
      script: "bun scripts/read.ts build/report-glob/\\\\*",
      deps: [{ target: "root:writes-report-glob" }],
    },
    "names-paths-outside-commands": {
      command: "set",
      script:
        '[[ -f build/report-glob/index.json ]] && for f in build/report-glob/*; do bun scripts/read.ts "$f"; done',
      deps: [],
    },
    "overrides-env": {
      command: "cargo",
      script:
        "RUSTUP_AUTO_INSTALL=1 cargo check --frozen\nRUSTUP_AUTO_INSTALL=1\nexport RUSTUP_AUTO_INSTALL=1\nfor RUSTUP_AUTO_INSTALL in 1; do cargo check --frozen; done\n(( RUSTUP_AUTO_INSTALL = 1 ))\ncargo check --frozen",
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    // Two astral characters before the dots: a code-point index would cut the prefix short of `build`.
    "names-an-astral-glob": {
      command: "bun",
      args: ["scripts/x.ts", "\u{1F4C1}\u{1F4C1}/../build/*"],
      deps: [],
    },
    "negates-a-command": { command: "bun", script: "! bun test", deps: [] },
    "expands-a-word": {
      command: "bun",
      script: `bun test $((RUSTUP_AUTO_INSTALL = 1)) "\${X:=1}"\nset -e <&$((RUSTUP_AUTO_INSTALL = 1, 0))\nbun test @($(bunx fixture-tool))\ncargo check --frozen`,
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    // A brace the shell reads opens an expansion the rules do not read, in a redirect and a range too.
    "expands-braces": {
      command: "bun",
      script:
        "bun in{stall,it} fixture-package\nbun scripts/read.ts build/x{1..2}/index.json\nbun scripts/read.ts >&build/y{1..2}\nbun {x..Z} fixture-tool",
      deps: [],
    },
    // A backslash-quoted brace, a heredoc's body, and its delimiter are text bash expands no brace in.
    "quotes-braces": {
      command: "bun",
      script:
        "bun scripts/read.ts in\\{stall,it\\}\nbun scripts/read.ts <<E{O,O}F\nin{stall,it}\nE{O,O}F",
      deps: [],
    },
    // A `..`, a dot-led pattern a bash without globskipdots may expand to `..`, or a brace alternative spelling
    // it, behind the first pattern segment climbs out of whatever that segment matched; one before it
    // normalizes, and `..x` is a name.
    "climbs-out-of-a-glob": {
      command: "bun",
      script: [
        "bun scripts/read.ts tmp*/../build/extension/manifest.json",
        "bun scripts/read.ts scripts*/.[.]/build/extension/manifest.json",
        "bun scripts/read.ts scripts*/.[[:punct:]]/build/extension/manifest.json",
        "bun scripts/read.ts {a,..}/build/extension/manifest.json",
        "bun scripts/read.ts {scripts/..,other}/build/extension/manifest.json",
        "bun scripts/read.ts tmp*/..x/y",
      ].join("\n"),
      deps: [],
    },
    "quotes-a-star-before-a-glob": {
      command: "bun",
      script: 'bun scripts/read.ts "foo*"/../build/x*',
      deps: [],
    },
    "process-substitutes-bunx": {
      command: "bun",
      script: "bun scripts/a.ts <(bunx fixture-tool)",
      deps: [],
    },
    // The parser keeps an extglob's pattern as text, so the substitution inside it is unread outside the gate too.
    "extglobs-outside-the-gate": {
      command: "bun",
      script: "bun test @($(bunx fixture-tool))",
      deps: [],
    },
    // A launcher runs one of its arguments; which one depends on its options, and `bun` may be one of them.
    "launches-bunx": { command: "command", script: "command bunx fixture-tool", deps: [] },
    "launches-aliased-bunx": { command: "env", script: "env -i X=1 bun x fixture-tool", deps: [] },
    "launches-bunx-past-a-bun-option": {
      command: "env",
      script: "env -u bun bunx fixture-tool",
      deps: [],
    },
    "launches-bunx-by-path": {
      command: "/usr/bin/env",
      script: "/usr/bin/env bunx fixture-tool",
      deps: [],
    },
    "times-out-bunx": { command: "timeout", script: "timeout 30s bun x fixture-tool", deps: [] },
    "launches-bunx-at-a-path": {
      command: "env",
      script: "env /opt/homebrew/bin/bunx fixture-tool",
      deps: [],
    },
    "times-bunx-by-path": {
      command: "/usr/bin/time",
      script: "/usr/bin/time -p bunx fixture-tool",
      deps: [],
    },
    "aliases-bunx-at-a-path": {
      command: "/opt/homebrew/bin/bun",
      args: ["x", "fixture-tool"],
      deps: [],
    },
    // Only the command's name, and the bun or bunx a launcher runs, is read by basename: an argument is a path.
    "names-a-path-ending-in-x": {
      command: "bun",
      args: ["scripts/read.ts", "fixtures/x", "fixtures/bunx"],
      deps: [],
    },
    "launches-inside-the-gate": { command: "env", script: "env bun test", deps: [] },
    // ANSI-C quoting decodes escapes the rules do not read.
    "quotes-ansi-c": { command: "bun", script: "bun $'in\\x73tall' fixture-package", deps: [] },
    "runs-bunx-through-bun-run": {
      command: "bun",
      args: ["run", "bunx", "fixture-tool"],
      deps: [],
    },
    // What runs is read from a literal command word only; after a launcher every word may be the command.
    "expands-the-command": {
      command: "$'bun\\x78'",
      script: "$'bun\\x78' fixture-tool\n$(echo bun) x fixture-tool\nenv $X fixture-tool",
      deps: [],
    },
  },
  extension: {
    build: {
      command: "bun",
      args: ["run", "build"],
      deps: [],
      outputFiles: { "build/extension": { optional: false } },
    },
    // Runs in src/apps/extension, so this word is src/apps/extension/build/extension, not the workspace artifact.
    pack: { command: "bun", args: ["scripts/pack.ts", "build/extension"], deps: [] },
  },
  core: {
    lint: {
      command: "cargo",
      args: ["clippy", "--frozen", "--all-targets", "--", "-D", "warnings"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
    "fmt-check": {
      command: "cargo",
      args: ["fmt", "--check"],
      deps: [],
      env: { RUSTUP_AUTO_INSTALL: "0" },
    },
  },
  web: { build: { command: "bun" } },
};

describe("auditGraph", () => {
  test("names every rule a task breaks, sorted: no bunx anywhere, own-toolchain commands with --frozen and RUSTUP_AUTO_INSTALL=0 and no bun install inside the gate's closure only, and every named build/ path ordered after its writer", () => {
    expect(auditGraph(graph)).toEqual(
      [
        "root:reads-built-without-dependency: names build/extension/chrome-mv3/manifest.json without depending on extension:build, which writes build/extension",
        "root:reads-dotted-path: names build/extension/chrome-mv3/manifest.json without depending on extension:build, which writes build/extension",
        "root:reads-spaced-path-without-dependency: names build/report html/index.json without depending on root:writes-spaced, which writes build/report html",
        "root:reads-redirected-build: names build/extension/result.json without depending on extension:build, which writes build/extension",
        "root:substitutes-bunx: runs bunx (bun's global cache stands in for a missing package)",
        "root:process-substitutes-bunx: runs bunx (bun's global cache stands in for a missing package)",
        "root:continues-a-word: runs bunx (bun's global cache stands in for a missing package)",
        `root:unparsable-script: unparsable script (1:18: reached EOF without matching \${ with })`,
        "root:reads-glob-word: names the glob build/report-glob/*; a reader under build/ declares the file or directory it reads",
        "root:glob-first-word: runs ./scripts/*.sh inside root:gate (not bun or a cargo toolchain verb)",
        "root:spaced-background-redirect: runs bunx (bun's global cache stands in for a missing package)",
        "root:spaced-background-redirect: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:escapes-words: bun install inside root:gate (installs)",
        "root:escapes-words: runs bunx (bun's global cache stands in for a missing package)",
        "root:escapes-words: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:escapes-words: names build/escaped/index.json, which no task's outputs write",
        "root:escapes-a-backslash-before-a-glob: names the glob build/report-glob/\\*; a reader under build/ declares the file or directory it reads",
        "root:names-paths-outside-commands: names build/report-glob/index.json without depending on root:writes-report-glob, which writes build/report-glob",
        "root:names-paths-outside-commands: names the glob build/report-glob/*; a reader under build/ declares the file or directory it reads",
        "root:overrides-env: RUSTUP_AUTO_INSTALL is assigned inside root:gate (the rules read the task's env, not its script's)",
        "root:overrides-env: RUSTUP_AUTO_INSTALL is assigned inside root:gate (the rules read the task's env, not its script's)",
        "root:overrides-env: runs export inside root:gate (not bun or a cargo toolchain verb)",
        "root:overrides-env: runs for inside root:gate (not bun or a cargo toolchain verb)",
        "root:negates-a-command: runs ! inside root:gate (not bun or a cargo toolchain verb)",
        "root:expands-a-word: the word $((...)) inside root:gate is not literal (the rules judge only what they can read)",
        "root:expands-a-word: the word $((...)) inside root:gate is not literal (the rules judge only what they can read)",
        `root:expands-a-word: the word \${X} inside root:gate is not literal (the rules judge only what they can read)`,
        "root:expands-a-word: the word ($(bunx fixture-tool)) holds an extglob pattern the parser keeps as text, so a command inside it is unread",
        "root:extglobs-outside-the-gate: the word ($(bunx fixture-tool)) holds an extglob pattern the parser keeps as text, so a command inside it is unread",
        "root:launches-bunx: runs bunx (bun's global cache stands in for a missing package)",
        "root:launches-aliased-bunx: runs bunx (bun's global cache stands in for a missing package)",
        "root:launches-bunx-past-a-bun-option: runs bunx (bun's global cache stands in for a missing package)",
        "root:launches-bunx-by-path: runs bunx (bun's global cache stands in for a missing package)",
        "root:times-out-bunx: runs bunx (bun's global cache stands in for a missing package)",
        "root:launches-bunx-at-a-path: runs bunx (bun's global cache stands in for a missing package)",
        "root:times-bunx-by-path: runs bunx (bun's global cache stands in for a missing package)",
        "root:aliases-bunx-at-a-path: runs bunx (bun's global cache stands in for a missing package)",
        "root:launches-inside-the-gate: runs env inside root:gate (not bun or a cargo toolchain verb)",
        "root:quotes-ansi-c: the word $'in\\x73tall' inside root:gate is not literal (the rules judge only what they can read)",
        "root:runs-bunx-through-bun-run: runs bunx (bun's global cache stands in for a missing package)",
        "root:expands-the-command: the command word $'bun\\x78' is not literal, so the auditor cannot tell what runs",
        "root:expands-the-command: the command word $(...) is not literal, so the auditor cannot tell what runs",
        `root:expands-the-command: the command word \${X} is not literal, so the auditor cannot tell what runs`,
        "root:expands-braces: the word in{stall,it} inside root:gate is not literal (the rules judge only what they can read)",
        "root:expands-braces: the word build/x{1..2}/index.json inside root:gate is not literal (the rules judge only what they can read)",
        "root:expands-braces: names the glob build/x{1..2}/index.json; a reader under build/ declares the file or directory it reads",
        "root:expands-braces: the word build/y{1..2} inside root:gate is not literal (the rules judge only what they can read)",
        "root:expands-braces: names the glob build/y{1..2}; a reader under build/ declares the file or directory it reads",
        "root:expands-braces: the word {x..Z} inside root:gate is not literal (the rules judge only what they can read)",
        "root:overrides-env: runs (( inside root:gate (not bun or a cargo toolchain verb)",
        "root:names-an-astral-glob: names the glob \u{1F4C1}\u{1F4C1}/../build/*; a reader under build/ declares the file or directory it reads",
        "root:quotes-a-star-before-a-glob: names the glob foo*/../build/x*; a reader under build/ declares the file or directory it reads",
        "root:climbs-out-of-a-glob: the path tmp*/../build/extension/manifest.json climbs out of a globbed segment, so the auditor cannot tell what it names",
        "root:climbs-out-of-a-glob: the path scripts*/.[.]/build/extension/manifest.json climbs out of a globbed segment, so the auditor cannot tell what it names",
        "root:climbs-out-of-a-glob: the path scripts*/.[[:punct:]]/build/extension/manifest.json climbs out of a globbed segment, so the auditor cannot tell what it names",
        "root:climbs-out-of-a-glob: the path {a,..}/build/extension/manifest.json climbs out of a globbed segment, so the auditor cannot tell what it names",
        "root:climbs-out-of-a-glob: the path {scripts/..,other}/build/extension/manifest.json climbs out of a globbed segment, so the auditor cannot tell what it names",
        "root:reads-dotted-glob: declares the glob input ./build/web/**/*; a reader under build/ declares the file or directory it reads",
        "root:reads-glob-build: declares the glob input build/web-pdf/**/*; a reader under build/ declares the file or directory it reads",
        "root:writes-glob: declares the glob output build/report-*/**/*; a writer under build/ declares the directory it writes",
        "root:reads-under-glob-writer: names build/report-html/index.html, which no task's outputs write",
        "root:check-yaml: runs uvx inside root:gate (not bun or a cargo toolchain verb)",
        "root:machete: runs cargo machete inside root:gate (not a toolchain verb)",
        "root:machete: cargo machete inside root:gate without --frozen",
        "root:fmt-ts: runs bunx (bun's global cache stands in for a missing package)",
        "root:quoted-runner: runs bunx (bun's global cache stands in for a missing package)",
        "root:auto-install: cargo doc inside root:gate without RUSTUP_AUTO_INSTALL=0 in env",
        "root:frozen-after-dashes: cargo clippy inside root:gate without --frozen",
        "root:sneaky-config: bun install inside root:gate (installs)",
        "root:sneaky-cwd: bun install inside root:gate (installs)",
        "root:sneaky-install: bun install inside root:gate (installs)",
        "root:sneaky-alias: bun i inside root:gate (installs)",
        "root:sneaky-cwd-x: runs bunx (bun's global cache stands in for a missing package)",
        "root:sneaky-cwd-x: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:sneaky-x: runs bunx (bun's global cache stands in for a missing package)",
        "root:sneaky-x: runs bunx inside root:gate (not bun or a cargo toolchain verb)",
        "root:unfetched: cargo doc inside root:gate without --frozen",
        "root:vanished: reachable from root:gate but not in the graph",
      ].sort(),
    );
  });

  test("a writer of the whole build directory covers every path under it, and a reader of a directory follows every writer inside it", () => {
    const whole: TaskGraph = {
      root: {
        gate: { command: "noop", deps: [{ target: "root:reads-anywhere" }] },
        "writes-build": { command: "bun", deps: [], outputFiles: { build: { optional: false } } },
        "writes-part": {
          command: "bun",
          deps: [],
          outputFiles: { "build/part": { optional: false } },
        },
        "reads-anywhere": {
          command: "bun",
          args: ["scripts/z.ts", "build/anything/at/all"],
          deps: [{ target: "root:writes-build" }],
        },
        "lists-build": { command: "bun", args: ["scripts/ls.ts", "build/"], deps: [] },
        "lists-dot-build": { command: "bun", args: ["scripts/ls.ts", "build/."], deps: [] },
        "lists-parent-of-part": {
          command: "bun",
          args: ["scripts/ls.ts", "build/part/.."],
          deps: [],
        },
      },
    };
    expect(auditGraph(whole)).toEqual([
      "root:lists-build: names build without depending on root:writes-build, which writes build",
      "root:lists-build: names build without depending on root:writes-part, which writes build/part",
      "root:lists-dot-build: names build without depending on root:writes-build, which writes build",
      "root:lists-dot-build: names build without depending on root:writes-part, which writes build/part",
      "root:lists-parent-of-part: names build without depending on root:writes-build, which writes build",
      "root:lists-parent-of-part: names build without depending on root:writes-part, which writes build/part",
    ]);
  });

  // mvdan-sh exposes a redirect's operator only as Go's enum number, so a release that renumbered them would
  // silently read a here-string as a file, or a file as a delimiter.
  test("every redirect form that opens a file names it, and a descriptor dup, a here-string, and a heredoc's body and delimiter do not", () => {
    const redirects: TaskGraph = {
      root: {
        gate: { command: "noop", deps: [] },
        redirects: {
          command: "bun",
          script: [
            "bun scripts/r.ts >build/o1 >>build/o2 <build/i1 <>build/io >|build/o3 &>build/o4 &>>build/o5 2>build/o6 >&build/o7 \\",
            "  2>&1 <&0 >&- <<<build/string <<E <<-D <<build/empty",
            "build/heredoc-body",
            "E",
            "build/dashed-body",
            "D",
            "build/empty",
          ].join("\n"),
          deps: [],
        },
      },
    };
    expect(auditGraph(redirects)).toEqual(
      ["i1", "io", "o1", "o2", "o3", "o4", "o5", "o6", "o7"].map(
        (name) => `root:redirects: names build/${name}, which no task's outputs write`,
      ),
    );
  });

  test("a graph without the gate reports the gate itself, not a clean census", () => {
    const { gate: _gate, ...rootWithoutGate } = graph.root ?? {};
    expect(auditGraph({ ...graph, root: rootWithoutGate })).toContain(
      `${GATE}: reachable from ${GATE} but not in the graph`,
    );
  });
});
