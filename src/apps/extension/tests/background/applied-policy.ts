import { POLICY_DEFAULTS, type PolicyValues } from "@chromium-bridge/shared/policy.gen";
import { fakeBrowser } from "wxt/testing/fake-browser";

/** Arm the cutover and store an in-scope applied policy, so a decision runs
 * under `overrides` instead of the pre-cutover deny baseline. `scope` is the
 * pinned key id, or null for the unpinned lane. */
export async function applyPolicy(
  overrides: Partial<PolicyValues>,
  scope: string | null = null,
): Promise<void> {
  await fakeBrowser.storage.local.set({
    bridgePolicyCutover: true,
    bridgePolicyState: {
      scope,
      effective: { ...POLICY_DEFAULTS, disabledTools: [], ...overrides },
      revision: 1,
      baselineB64: "ZG9j",
      at: 1,
    },
  });
}
