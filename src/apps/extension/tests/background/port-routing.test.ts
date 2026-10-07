// Frame routing is strict: every host->extension control frame tag in the
// generated wire table is claimed by exactly one collaborator, and a bridge
// request by none. port.ts hands a frame to the FIRST collaborator that
// claims it, so an overlapping guard (a module that stopped pinning `type`,
// or a new frame two modules both recognize) would route silently to
// whichever registered first; this pins the guards disjoint over the table
// the Rust core generates, with the real modules behind the registry.

import { GENERATED_WIRE_FRAMES } from "@chromium-bridge/shared/generated/envelope";
import { beforeEach, describe, expect, test } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { collaborators } from "@/lib/background/port";

// The host->extension control tags from the generated wire table, plus the server's `cancel` signal (generated
// beside the envelopes, not in the control table), which the dispatch collaborator owns.
const CONTROL_TAGS = [...Object.values(GENERATED_WIRE_FRAMES).flat(), "cancel"];

beforeEach(() => {
  fakeBrowser.reset();
});

describe("frame routing over the generated wire table", () => {
  test.each(CONTROL_TAGS)("%s is claimed by exactly one collaborator", (tag) => {
    // `ok` is the one field a result frame's base schema requires beyond the
    // tag; the classification-only guards ignore it. With nothing
    // outstanding every handler drops the frame as unsolicited.
    const frame = { type: tag, ok: true };
    const claims = collaborators.map((c) => c.onFrame?.(frame) ?? false);
    expect(
      claims.filter(Boolean),
      `${tag} claimed by ${claims.filter(Boolean).length}`,
    ).toHaveLength(1);
  });

  test("a bridge request is claimed by no collaborator", () => {
    const req = { id: 1, op: "tab_list", args: {} };
    expect(collaborators.map((c) => c.onFrame?.(req) ?? false)).toEqual(
      collaborators.map(() => false),
    );
  });
});
