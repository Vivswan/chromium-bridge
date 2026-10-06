#!/usr/bin/env bun
// One layering declaration (architecture.yml), two readers: this lint and the
// module map (render-architecture-map.ts). The lint fails in both directions so
// the declaration cannot rot:
//   import between layers with no declared edge  -> "forbidden import", exit 1
//   declared edge no file draws                  -> "stale allowance", exit 1
//   layer that owns no source file               -> exit 1, never a declaration that matches any tree
//   computed import() or require()               -> exit 2, never a silently dropped edge
//
// An edge is any way one file names another: runtime imports, type-only
// imports, re-exports, `import("./x").T` in a type position, and
// `import X = require("./x")`. A specifier is followed when it is relative or
// starts with a prefix the declaration's `aliases` map to a directory; the
// extension reaches the shared package only through such aliases
// (`@chromium-bridge/shared/`, WXT's `@/`), so without them those edges would
// be invisible and an undeclared dependency would pass.

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { parseArgs } from "node:util";
import { type Node, parseSync, type TemplateElement } from "oxc-parser";
import { z } from "zod";
import { realpath } from "./repo-paths";

export const DEFAULT_CONFIG = "architecture.yml";

const StringList = z.array(z.string());
const Declaration = z.strictObject({
  // layer -> the repo-relative paths it owns; a trailing slash means a directory.
  layers: z.record(z.string(), StringList),
  // Glob patterns of files that are not sources of the graph (tests, fixtures). An import INTO one is still an edge.
  exclude: StringList.default([]),
  // from -> the layers it may import; a layer absent here imports nothing outside itself.
  edges: z.record(z.string(), StringList).default({}),
  // specifier prefix -> the repo-relative directory it stands for, both slash-terminated.
  aliases: z.record(z.string(), z.string()).default({}),
});

export type Architecture = z.infer<typeof Declaration>;

export const SOURCE_EXTENSIONS = [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"];

/** A repository-relative path has no leading slash and no `.` or `..` segment; the scanner emits `src/main.ts`, never `./src/main.ts`. */
function checkRepoRelative(label: string, owner: string, path: string): void {
  if (path.startsWith("/") || path.split("/").includes("..")) {
    throw new Error(
      `${label}: ${owner} names ${path}, which leaves the repository; paths are repository-relative`,
    );
  }
  if (path.split("/").includes(".")) {
    throw new Error(`${label}: ${owner} names ${path}; write it without the . segment`);
  }
}

/** The declaration at `path`, shape-checked: a typo in a layer name under edges is an error here, not a silent pass. */
export function readArchitecture(path: string, label = path): Architecture {
  const parsed = Declaration.safeParse(Bun.YAML.parse(readFileSync(path, "utf8")));
  if (!parsed.success) throw new Error(`${label}: ${z.prettifyError(parsed.error)}`);
  const arch = parsed.data;
  if (Object.keys(arch.layers).length === 0) {
    throw new Error(`${label}: layers must map each layer name to a list of paths`);
  }
  for (const [from, targets] of Object.entries(arch.edges)) {
    for (const name of [from, ...targets]) {
      if (!Object.hasOwn(arch.layers, name)) {
        throw new Error(`${label}: edges name "${name}", which is not a layer`);
      }
    }
  }
  for (const [layer, paths] of Object.entries(arch.layers)) {
    for (const path of paths) checkRepoRelative(label, `layer ${layer}`, path);
  }
  for (const [prefix, dir] of Object.entries(arch.aliases)) {
    if (
      prefix === "" ||
      !prefix.endsWith("/") ||
      prefix.startsWith(".") ||
      prefix.startsWith("/")
    ) {
      throw new Error(
        `${label}: alias "${prefix}" must be a bare specifier prefix ending in a slash, such as "@scope/pkg/"`,
      );
    }
    if (!dir.endsWith("/")) {
      throw new Error(`${label}: alias "${prefix}" must map to a directory written as ${dir}/`);
    }
    checkRepoRelative(label, `alias "${prefix}"`, dir);
  }
  // layerOf takes the first match in YAML order, so an overlap would hand
  // one layer's files to another silently; the declaration refuses it instead.
  const owned = Object.entries(arch.layers).flatMap(([layer, paths]) =>
    paths.map((path) => ({ layer, path })),
  );
  for (const [i, a] of owned.entries()) {
    for (const b of owned.slice(i + 1)) {
      if (a.layer === b.layer) continue;
      const overlap =
        a.path === b.path ||
        (a.path.endsWith("/") && b.path.startsWith(a.path)) ||
        (b.path.endsWith("/") && a.path.startsWith(b.path));
      if (overlap) {
        const inner = a.path.length >= b.path.length ? a.path : b.path;
        throw new Error(
          `${label}: layers ${a.layer} and ${b.layer} overlap on ${inner}; a file has one owner`,
        );
      }
    }
  }
  return arch;
}

export function layerOf(arch: Architecture, path: string): string | undefined {
  return Object.entries(arch.layers).find(([, paths]) =>
    paths.some((owned) => (owned.endsWith("/") ? path.startsWith(owned) : path === owned)),
  )?.[0];
}

// --- source scanning ---------------------------------------------------------

export function* nodesOf(value: unknown): Generator<Node> {
  if (Array.isArray(value)) {
    for (const item of value) yield* nodesOf(item);
    return;
  }
  if (typeof value !== "object" || value === null) return;
  if ("type" in value && typeof value.type === "string") yield value as Node;
  for (const [key, child] of Object.entries(value)) {
    if (key !== "parent") yield* nodesOf(child);
  }
}

// Wrappers that change nothing about what runs: `(require)("./m")`, `require!("./m")`,
// `(require as NodeRequire)("./m")`, `(require satisfies X)("./m")`, `(<X>require)("./m")` all load.
const WRAPPERS = new Set([
  "ParenthesizedExpression",
  "TSNonNullExpression",
  "TSAsExpression",
  "TSSatisfiesExpression",
  "TSTypeAssertion",
]);

function unwrapped(node: Node): Node {
  let current = node;
  while (WRAPPERS.has(current.type)) {
    current = (current as unknown as { expression: Node }).expression;
  }
  return current;
}

function literalSpecifier(node: Node | null | undefined): string | undefined {
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  if (node?.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis
      .map((quasi: TemplateElement) => quasi.value.cooked ?? quasi.value.raw)
      .join("");
  }
  return undefined;
}

/**
 * Every module specifier `text` names, runtime and type-level alike, bare
 * package names included (the caller decides which are edges). A computed
 * `import(x)` or `require(x)` throws, naming file and line: a missing edge is
 * the one failure this lint exists to catch, so the file is rewritten, not skipped.
 */
export function importSpecifiers(text: string, file: string): string[] {
  const { program, module, errors } = parseSync(file, text);
  const lineOf = (offset: number): number => text.slice(0, offset).split("\n").length;
  const [error] = errors;
  if (error) {
    throw new Error(
      `${file}:${lineOf(error.labels[0]?.start ?? 0)} does not parse: ${error.message}`,
    );
  }
  const found = new Set<string>();
  for (const entry of module.staticImports) found.add(entry.moduleRequest.value);
  for (const statement of module.staticExports) {
    for (const entry of statement.entries) {
      if (entry.moduleRequest) found.add(entry.moduleRequest.value);
    }
  }
  const computed = (offset: number): never => {
    throw new Error(
      `${file}:${lineOf(offset)} loads a module through a computed specifier, which the import graph cannot follow; use a string literal`,
    );
  };
  for (const node of nodesOf(program)) {
    if (node.type === "ImportExpression") {
      found.add(literalSpecifier(unwrapped(node.source)) ?? computed(node.start));
    } else if (node.type === "CallExpression") {
      const callee = unwrapped(node.callee);
      if (isRequireCallee(callee)) {
        const [argument] = node.arguments;
        found.add(
          literalSpecifier(argument === undefined ? undefined : unwrapped(argument)) ??
            computed(node.start),
        );
      }
    } else if (node.type === "TSImportType") {
      found.add(node.source.value);
    } else if (node.type === "TSExternalModuleReference") {
      found.add(node.expression.value);
    }
  }
  return [...found];
}

/** `require(...)` and CommonJS's `module.require(...)` both load; `require.resolve(...)` does not. */
function isRequireCallee(callee: Node): boolean {
  if (callee.type === "Identifier") return callee.name === "require";
  if (callee.type !== "MemberExpression" || callee.computed) return false;
  const { object: receiver, property } = callee as unknown as { object: Node; property: Node };
  const object = unwrapped(receiver);
  return (
    object.type === "Identifier" &&
    object.name === "module" &&
    property.type === "Identifier" &&
    property.name === "require"
  );
}

function isFile(path: string): boolean {
  return existsSync(path) && statSync(path).isFile();
}

/**
 * The file at `target` as a bundler resolves it: as written, with a source extension, or as an
 * index file; nothing found throws with `importLabel`.
 */
function resolveTarget(target: string, importLabel: string): string {
  if (isFile(target)) return target;
  const stem = target.replace(/\.(?:[mc]?[jt]sx?)$/, "");
  const candidates = [
    ...SOURCE_EXTENSIONS.map((ext) => `${stem}${ext}`),
    ...SOURCE_EXTENSIONS.map((ext) => join(target, `index${ext}`)),
  ];
  const found = candidates.find(isFile);
  if (found === undefined) {
    throw new Error(`${importLabel}, which resolves to no file (tried ${candidates.join(", ")})`);
  }
  return found;
}

const isRelative = (specifier: string): boolean => /^\.\.?\//.test(specifier);

export function resolveEdge(
  root: string,
  arch: Architecture,
  importer: string,
  specifier: string,
): string | undefined {
  if (isRelative(specifier)) {
    return resolveTarget(
      resolve(dirname(importer), specifier),
      `${importer} imports "${specifier}"`,
    );
  }
  const alias = Object.entries(arch.aliases).find(([prefix]) => specifier.startsWith(prefix));
  if (alias === undefined) return undefined;
  const [prefix, dir] = alias;
  return resolveTarget(
    join(root, dir, specifier.slice(prefix.length)),
    `${importer} imports "${specifier}" (alias ${prefix} -> ${dir})`,
  );
}

// --- the lint ----------------------------------------------------------------

function toPosix(path: string): string {
  return path.split("\\").join("/");
}

/** The top-level directories the layers live in, so a file beside them outside every layer is seen. */
function scanRoots(arch: Architecture): string[] {
  const roots = new Set<string>();
  for (const paths of Object.values(arch.layers)) {
    for (const path of paths) {
      const [head] = path.split("/");
      if (head !== undefined && head !== "" && path.includes("/")) roots.add(head);
    }
  }
  return [...roots].sort();
}

// Dependency stores and dot-directories (.wxt, .astro) sit under src/ beside the sources; they are
// never sources, and pruning them here keeps the walk off the thousands of files an exclude glob
// would still visit.
const PRUNED_DIRECTORY = (name: string): boolean => name === "node_modules" || name.startsWith(".");

function* sourceFiles(root: string, dir: string): Generator<string> {
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!PRUNED_DIRECTORY(entry.name)) yield* sourceFiles(root, path);
    } else if (entry.isFile() && SOURCE_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
      yield path;
    }
  }
}

/**
 * The lint verdict for the tree at `root`. Empty means the declaration is
 * exactly the tree. `configLabel` is how the messages name the declaration file.
 */
export function lintArchitecture(
  root: string,
  arch: Architecture,
  configLabel = DEFAULT_CONFIG,
): string[] {
  const excluded = arch.exclude.map((pattern) => new Bun.Glob(pattern));
  const isExcluded = (file: string): boolean => excluded.some((glob) => glob.match(file));
  const drawn = new Map<string, string[]>();
  const owned = new Map<string, number>(Object.keys(arch.layers).map((layer) => [layer, 0]));
  const problems: string[] = [];
  for (const [layer, paths] of Object.entries(arch.layers)) {
    for (const path of paths) {
      if (!existsSync(join(root, path))) {
        problems.push(`layer ${layer} names ${path}, which does not exist`);
      } else if (!path.endsWith("/") && statSync(join(root, path)).isDirectory()) {
        // Without the slash no scan root reaches the directory, and the layer would lint as empty.
        problems.push(
          `layer ${layer} names ${path}, a directory; write it as ${path}/ so its files are scanned`,
        );
      }
    }
  }
  for (const [prefix, dir] of Object.entries(arch.aliases)) {
    if (!existsSync(join(root, dir))) {
      problems.push(`alias "${prefix}" names ${dir}, which does not exist`);
    }
  }
  const files: string[] = [];
  // A layer may own a root-level file (main.ts); no scan root reaches it, so it is seeded by name.
  for (const paths of Object.values(arch.layers)) {
    for (const path of paths) {
      if (path.includes("/") || !SOURCE_EXTENSIONS.some((ext) => path.endsWith(ext))) continue;
      if (isFile(join(root, path)) && !isExcluded(path)) files.push(path);
    }
  }
  for (const scanRoot of scanRoots(arch)) {
    if (!existsSync(join(root, scanRoot))) continue;
    for (const file of sourceFiles(root, scanRoot)) {
      if (!isExcluded(file)) files.push(file);
    }
  }
  for (const file of files.sort()) {
    const from = layerOf(arch, file);
    if (from === undefined) {
      problems.push(`${file} belongs to no layer in ${configLabel}`);
      continue;
    }
    owned.set(from, (owned.get(from) ?? 0) + 1);
    const absolute = join(root, file);
    for (const specifier of importSpecifiers(readFileSync(absolute, "utf8"), file)) {
      const resolved = resolveEdge(root, arch, absolute, specifier);
      // A stylesheet or asset import names no module, so only a source file is a node of the graph.
      if (resolved === undefined || !SOURCE_EXTENSIONS.some((ext) => resolved.endsWith(ext))) {
        continue;
      }
      const target = toPosix(relative(root, resolved));
      const to = layerOf(arch, target);
      if (to === undefined) {
        problems.push(`${target} (imported by ${file}) belongs to no layer in ${configLabel}`);
      } else if (to !== from) {
        const key = `${from} -> ${to}`;
        drawn.set(key, [...(drawn.get(key) ?? []), `${file} -> ${target}`]);
      }
    }
  }
  // The stale direction for layers; it also means a declaration that reaches no file cannot pass.
  for (const [layer, count] of owned) {
    if (count === 0)
      problems.push(`layer ${layer} owns no source file; fix its paths or remove it`);
  }
  const declared = new Set(
    Object.entries(arch.edges).flatMap(([from, targets]) =>
      targets.map((to) => `${from} -> ${to}`),
    ),
  );
  for (const [key, sites] of [...drawn].sort()) {
    if (!declared.has(key)) {
      problems.push(`forbidden import ${key}: ${sites.join(", ")}; move it or declare the edge`);
    }
  }
  for (const key of [...declared].sort()) {
    if (!drawn.has(key)) {
      problems.push(`stale allowance ${key}: no file draws it; remove it from ${configLabel}`);
    }
  }
  return problems;
}

/**
 * The module map over the DECLARED edges. A hyphen or slash in a layer name is edge syntax to
 * mermaid, so ids use underscores; two names that collapse to one id (api-v1, api_v1) get a
 * numbered suffix, so no node is drawn over another.
 */
const MERMAID_KEYWORDS = new Set([
  "end",
  "graph",
  "flowchart",
  "subgraph",
  "style",
  "class",
  "classdef",
  "click",
  "linkstyle",
  "direction",
]);

export function renderArchitectureMermaid(arch: Architecture): string {
  const ids = new Map<string, string>();
  const taken = new Set<string>();
  for (const layer of Object.keys(arch.layers)) {
    const sanitized = layer.replace(/[^A-Za-z0-9_]/g, "_");
    // `end` and the other flowchart keywords break the parse as node ids; a trailing underscore keeps the name readable.
    const base = MERMAID_KEYWORDS.has(sanitized.toLowerCase()) ? `${sanitized}_` : sanitized;
    let candidate = base;
    for (let n = 2; taken.has(candidate); n++) candidate = `${base}_${n}`;
    taken.add(candidate);
    ids.set(layer, candidate);
  }
  const id = (layer: string): string => ids.get(layer) ?? layer;
  return [
    "graph TD",
    ...Object.entries(arch.layers).map(([name, paths]) => `  ${id(name)}["${paths.join("<br>")}"]`),
    ...Object.entries(arch.edges).flatMap(([from, targets]) =>
      targets.map((to) => `  ${id(from)} --> ${id(to)}`),
    ),
  ].join("\n");
}

// --- CLI ---------------------------------------------------------------------

const USAGE = [
  "usage: arch-lint.ts [--config <architecture.yml>] [--root <dir>] [--mermaid]",
  "  --config   the layering declaration (default: <root>/architecture.yml)",
  "  --root     the repository root the paths are relative to (default: cwd)",
  "  --mermaid  print the module map instead of linting",
  "exit 0: the tree matches the declaration; 1: forbidden or stale edges; 2: usage or an unreadable graph",
].join("\n");

export interface CliOptions {
  root: string;
  config: string;
  mermaid: boolean;
}

/** How messages name `path`: relative to `root` when it lives inside, absolute otherwise. */
export function pathLabel(root: string, path: string): string {
  const rel = toPosix(relative(realpath(root), realpath(path)));
  return rel === "" || rel.startsWith("..") || isAbsolute(rel) ? toPosix(path) : rel;
}

export function parseCli(argv: readonly string[]): CliOptions {
  try {
    const { values } = parseArgs({
      args: [...argv],
      options: {
        config: { type: "string" },
        root: { type: "string" },
        mermaid: { type: "boolean" },
      },
      strict: true,
    });
    const root = realpath(values.root ?? process.cwd());
    return {
      root,
      config: values.config === undefined ? join(root, DEFAULT_CONFIG) : realpath(values.config),
      mermaid: values.mermaid === true,
    };
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\n${USAGE}`);
  }
}

if (import.meta.main) {
  let options: CliOptions;
  try {
    options = parseCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  }
  const configLabel = pathLabel(options.root, options.config);
  try {
    const arch = readArchitecture(options.config, configLabel);
    if (options.mermaid) {
      console.log(renderArchitectureMermaid(arch));
      process.exit(0);
    }
    const problems = lintArchitecture(options.root, arch, configLabel);
    if (problems.length > 0) {
      console.error(`arch-lint: ${problems.length} problem(s)\n  ${problems.join("\n  ")}`);
      process.exit(1);
    }
    console.log(`arch-lint: imports under ${scanRoots(arch).join(", ")} match ${configLabel}`);
  } catch (error) {
    console.error(`arch-lint: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(2);
  }
}
