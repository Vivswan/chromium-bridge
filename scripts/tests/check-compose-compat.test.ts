// The gate's negative controls: docker compose accepts every key below and podman-compose ignores or
// rejects it, and no engine fails a compose file over them, so only this check can. The cases are the
// known-divergent keys and the two ways a mount option could reach the engine unseen; the portable
// fixture is the shape compose.yaml uses, interpolations included.

import { describe, expect, test } from "bun:test";
import { nonPortableKeys } from "../check-compose-compat";

const portable = {
  "x-ci": { image: "example-ci" },
  services: {
    ci: {
      build: { context: ".", dockerfile: "Containerfile" },
      image: "example-ci",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: compose interpolation syntax, read as compose reads it
      user: "${UID:-1000}:${GID:-1000}",
      working_dir: "/work",
      init: true,
      shm_size: "1gb",
      environment: { GENKAN_REQUIRE_BROWSER: "1" },
      command: ["moon", "run", "ci"],
      volumes: [
        "./:/work:z",
        {
          type: "bind",
          // biome-ignore lint/suspicious/noTemplateCurlyInString: compose interpolation syntax, read as compose reads it
          source: "${GIT_DIR:-./.git}",
          // biome-ignore lint/suspicious/noTemplateCurlyInString: compose interpolation syntax, read as compose reads it
          target: "${GIT_DIR:-/work/.git}",
          read_only: true,
          bind: { selinux: "z" },
        },
        "cargo-target:/work/target",
        { type: "volume", source: "bun-cache", target: "/home/ci/.bun/install/cache" },
      ],
      userns_mode: "keep-id:uid=1000,gid=1000",
    },
  },
  volumes: { "cargo-target": null, "bun-cache": {} },
};

const withService = (extra: Record<string, unknown>) => ({
  ...portable,
  services: { ci: { ...portable.services.ci, ...extra } },
});

describe("nonPortableKeys", () => {
  test("the subset both engines implement passes", () => {
    expect(nonPortableKeys(portable)).toEqual([]);
  });

  test("x- extension fields pass at every level, as the specification allows them", () => {
    const doc = {
      ...withService({ "x-note": "service level", build: { context: ".", "x-stage": "nested" } }),
      volumes: { "cargo-target": { "x-owner": "ci" } },
    };
    expect(nonPortableKeys(doc)).toEqual([]);
  });

  test.each([
    [
      "the legacy version key",
      { ...portable, version: "3.9" },
      'compose: Unrecognized key: "version"',
    ],
    [
      "docker's develop/watch file sync",
      withService({ develop: { watch: [] } }),
      'compose.services.ci: Unrecognized key: "develop"',
    ],
    [
      "a service whose own name starts with x-, which is a name, not an extension field",
      { ...portable, services: { "x-ci": { image: "example-ci", privileged: true } } },
      'compose.services.x-ci: Unrecognized key: "privileged"',
    ],
    [
      "an inherited Object property name used as a key",
      withService({ constructor: [] }),
      'compose.services.ci: Unrecognized key: "constructor"',
    ],
    [
      "a service named __proto__, which zod's record parser would skip unvalidated",
      // JSON.parse yields an own "__proto__" key, as Bun.YAML.parse does; an object literal would set the prototype.
      {
        ...portable,
        services: JSON.parse('{"__proto__": {"image": "example-ci", "privileged": true}}'),
      },
      "compose.services.__proto__: reserved key",
    ],
    [
      "a Docker Desktop mount hint",
      withService({ volumes: ["./:/work:cached"] }),
      'compose.services.ci.volumes[0]: mount option "cached" is not portable (allowed: ro, rw, z, Z)',
    ],
    [
      "a short mount whose interpolation default could carry a mount hint",
      // biome-ignore lint/suspicious/noTemplateCurlyInString: compose interpolation syntax, read as compose reads it
      withService({ volumes: ["./:${DEST:-/work:cached}"] }),
      "compose.services.ci.volumes[0]: an interpolated mount must use the long form (type/source/target)",
    ],
    [
      "a long mount with an SELinux label docker compose rejects",
      withService({
        volumes: [{ type: "bind", source: "./", target: "/work", bind: { selinux: "U" } }],
      }),
      'compose.services.ci.volumes[0].bind.selinux: Invalid option: expected one of "z"|"Z"',
    ],
    [
      "bind options on a named volume, which docker compose drops with only a warning",
      withService({
        volumes: [
          { type: "volume", source: "bun-cache", target: "/cache", bind: { selinux: "z" } },
        ],
      }),
      'compose.services.ci.volumes[0]: Unrecognized key: "bind"',
    ],
  ])("rejects %s, naming the path", (_name, doc, finding) => {
    expect(nonPortableKeys(doc)).toEqual([finding]);
  });
});
