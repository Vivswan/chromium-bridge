#!/usr/bin/env bun
// compose.yaml and compose.podman.yaml must run under both `docker compose` and `podman compose`.
// Docker accepts keys podman-compose ignores or rejects, and neither engine fails a file over them, so
// this gate holds both files to the Compose Specification subset the two engines implement.
//
//   version                     -> legacy, ignored by docker, rejected by older podman-compose
//   develop (watch), extends    -> docker's file sync and inheritance; podman-compose ignores them
//   privileged, network_mode,   -> not in the subset by choice: the container's isolation from the
//   cap_add, devices, ports        host is the point of the file
//   volume ":cached"/":delegated" -> Docker Desktop mount hints podman rejects
//
// Run via `moon run check-compose` (part of the ci gate).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { repoRoot } from "./lib.ts";

const MOUNT_OPTIONS = new Set(["ro", "rw", "z", "Z"]);

const isMapping = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

// `x-` extension fields are Compose Specification keys of every object (compose.yaml keeps its YAML
// anchors in one) and are dropped before the strict parse. Only objects: the names under services,
// volumes, and environment are the user's, and a service called x-ci is still a service.
function extensible<T extends z.ZodRawShape>(shape: T) {
  return z.preprocess(
    (value) =>
      isMapping(value)
        ? Object.fromEntries(Object.entries(value).filter(([key]) => !key.startsWith("x-")))
        : value,
    z.strictObject(shape),
  );
}

// Short syntax stays literal: compose interpolates `${...}` before it splits on ":", so a default or
// a value carrying ":cached" would reach the engine unseen. An interpolated mount takes the long form,
// whose options are structured fields a variable cannot reach.
const shortMount = z.string().superRefine((mount, ctx) => {
  if (mount.includes("$")) {
    ctx.addIssue({
      code: "custom",
      message: "an interpolated mount must use the long form (type/source/target)",
    });
    return;
  }
  const segments = mount.split(":");
  if (segments.length < 2 || segments.length > 3 || segments.some((segment) => segment === "")) {
    ctx.addIssue({ code: "custom", message: `expected source:target[:options], got ${mount}` });
    return;
  }
  for (const option of segments[2]?.split(",") ?? []) {
    if (!MOUNT_OPTIONS.has(option)) {
      ctx.addIssue({
        code: "custom",
        message: `mount option "${option}" is not portable (allowed: ro, rw, z, Z)`,
      });
    }
  }
});

const longMount = extensible({
  type: z.enum(["bind", "volume"]),
  source: z.string(),
  target: z.string(),
  read_only: z.boolean().optional(),
  bind: extensible({ selinux: z.enum(["z", "Z"]).optional() }).optional(),
});

// Dispatched by shape rather than a zod union, so a finding names the failing field instead of the
// union's generic "Invalid input".
const mount = z.unknown().superRefine((value, ctx) => {
  const result = (typeof value === "string" ? shortMount : longMount).safeParse(value);
  if (result.success) return;
  for (const issue of result.error.issues) ctx.addIssue({ ...issue, path: [...issue.path] });
});

const stringOrList = z.union([z.string(), z.array(z.string())]);

const service = extensible({
  build: extensible({
    context: z.string().optional(),
    dockerfile: z.string().optional(),
  }).optional(),
  image: z.string().optional(),
  command: stringOrList.optional(),
  entrypoint: stringOrList.optional(),
  environment: z.record(z.string(), z.string()).optional(),
  init: z.boolean().optional(),
  shm_size: z.union([z.string(), z.number()]).optional(),
  stdin_open: z.boolean().optional(),
  tty: z.boolean().optional(),
  user: z.string().optional(),
  userns_mode: z.string().optional(),
  working_dir: z.string().optional(),
  volumes: z.array(mount).optional(),
});

// A named volume takes engine defaults: `name:` (null) or `name: {}`.
const namedVolume = z.union([z.null(), extensible({})]);

const composeFile = extensible({
  name: z.string().optional(),
  services: z.record(z.string(), service).optional(),
  volumes: z.record(z.string(), namedVolume).optional(),
});

// zod's record parser skips a `__proto__` entry instead of validating it, so a service under that
// name would pass with any settings; it is refused before parsing, at every depth.
function reservedKeys(value: unknown, path: string): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => reservedKeys(item, `${path}[${index}]`));
  }
  if (!isMapping(value)) return [];
  return Object.entries(value).flatMap(([key, child]) =>
    key === "__proto__" ? [`${path}.${key}: reserved key`] : reservedKeys(child, `${path}.${key}`),
  );
}

/** Every key or value outside the portable subset, as `path: reason` lines. */
export function nonPortableKeys(doc: unknown): string[] {
  const reserved = reservedKeys(doc, "compose");
  if (reserved.length > 0) return reserved;
  const result = composeFile.safeParse(doc);
  if (result.success) return [];
  return result.error.issues.map((issue) => {
    const path = issue.path
      .map((part) => (typeof part === "number" ? `[${part}]` : `.${String(part)}`))
      .join("");
    return `compose${path}: ${issue.message}`;
  });
}

if (import.meta.main) {
  let failed = false;
  for (const file of ["compose.yaml", "compose.podman.yaml"]) {
    const findings = nonPortableKeys(Bun.YAML.parse(readFileSync(join(repoRoot, file), "utf8")));
    for (const finding of findings) console.error(`${file}: ${finding}`);
    failed ||= findings.length > 0;
  }
  if (!failed) console.log("compose files stay within the docker + podman portable subset");
  process.exit(failed ? 1 : 0);
}
