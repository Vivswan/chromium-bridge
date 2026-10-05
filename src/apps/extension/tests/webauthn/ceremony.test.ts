// The page half of the WebAuthn ceremonies, driven with a fake browser client. What the browser does with
// the options (prompt, sign) is the isolated-browser suite's (tests/browser/webauthn_test.ts); this pins
// the shapes the page hands the API and the frames it builds from the API's answers, both external
// contracts: the host parses the frames, the WebAuthn client the options.

import type {
  EnrollOptionsFrame,
  PresenceRequestFrame,
} from "@chromium-bridge/shared/envelope.gen";
import { describe, expect, test } from "vitest";
import {
  assert,
  CEREMONY_TIMEOUT_MS,
  creationOptions,
  presenceSurface,
  register,
  requestOptions,
  type WebAuthnClient,
} from "@/lib/shared/webauthn-ceremony";

const RP_ID = "mkjjlmjbcljpcfkfadfmhblmmddkdihf";

const enrollOptions: EnrollOptionsFrame = {
  type: "enroll_options",
  challenge: "Y2hhbGxlbmdl",
  nonce: "nonce-0001",
  user_id: "dXNlci1pZA",
  user_name: "brave",
  exclude_credential_ids: ["Y3JlZC1h", "Y3JlZC1i"],
};

const presenceRequest: PresenceRequestFrame = {
  type: "presence_request",
  challenge: "cHJlc2VuY2U",
  nonce: "nonce-0002",
  action: "pair_client:codex",
  allowed_credential_ids: ["Y3JlZC1h"],
};

/** A browser client that records what it was asked and answers with a fixed credential JSON. */
function fakeClient(response: Record<string, unknown>, rawId = "Y3JlZC1h") {
  const calls: { create?: unknown; get?: unknown } = {};
  const credential = {
    id: rawId,
    rawId,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response,
  };
  const client: WebAuthnClient = {
    create: async (options) => {
      calls.create = options;
      return credential as unknown as RegistrationResponseJSON;
    },
    get: async (options) => {
      calls.get = options;
      return credential as unknown as AuthenticationResponseJSON;
    },
  };
  return { client, calls };
}

describe("creation and request options", () => {
  test("enroll_options becomes creation options with RP ID = the extension id, ES256 only, attestation none", () => {
    // The host verifies ES256 alone and never trusts attestation; an authenticator offered another
    // algorithm or asked for attestation would hand the host a credential it refuses.
    expect(creationOptions(enrollOptions, RP_ID)).toEqual({
      rp: { id: RP_ID, name: "Chromium Bridge" },
      user: { id: "dXNlci1pZA", name: "brave", displayName: "brave" },
      challenge: "Y2hhbGxlbmdl",
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [
        { type: "public-key", id: "Y3JlZC1h" },
        { type: "public-key", id: "Y3JlZC1i" },
      ],
      authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
      attestation: "none",
      timeout: CEREMONY_TIMEOUT_MS,
    });
  });

  test("presence_request becomes request options scoped to the enrolled credentials", () => {
    expect(requestOptions(presenceRequest, RP_ID)).toEqual({
      rpId: RP_ID,
      challenge: "cHJlc2VuY2U",
      allowCredentials: [{ type: "public-key", id: "Y3JlZC1h" }],
      userVerification: "preferred",
      timeout: CEREMONY_TIMEOUT_MS,
    });
  });
});

describe("responses become the frames the host parses", () => {
  test("a create response becomes enroll_finish's two fields", async () => {
    const { client, calls } = fakeClient({
      clientDataJSON: "Y2xpZW50LWRhdGE",
      attestationObject: "YXR0ZXN0YXRpb24",
      transports: ["internal"],
    });
    await expect(register(enrollOptions, client, RP_ID)).resolves.toEqual({
      attestation_object: "YXR0ZXN0YXRpb24",
      client_data_json: "Y2xpZW50LWRhdGE",
    });
    expect(calls.create).toEqual(creationOptions(enrollOptions, RP_ID));
  });

  test("a get response becomes presence_assert's four fields, the credential id from rawId", async () => {
    const { client, calls } = fakeClient(
      {
        clientDataJSON: "Y2xpZW50LWRhdGE",
        authenticatorData: "YXV0aC1kYXRh",
        signature: "c2ln",
        userHandle: null,
      },
      "Y3JlZC1h",
    );
    await expect(assert(presenceRequest, client, RP_ID)).resolves.toEqual({
      credential_id: "Y3JlZC1h",
      authenticator_data: "YXV0aC1kYXRh",
      client_data_json: "Y2xpZW50LWRhdGE",
      signature: "c2ln",
    });
    expect(calls.get).toEqual(requestOptions(presenceRequest, RP_ID));
  });

  test("a response of the other ceremony's shape throws instead of posting a half frame", async () => {
    // A create answered with an assertion (or the reverse) would otherwise reach the host as a frame with
    // undefined fields; the host would refuse it, but the page fails first and names the cause.
    const assertionShaped = fakeClient({
      clientDataJSON: "x",
      authenticatorData: "y",
      signature: "z",
    });
    await expect(register(enrollOptions, assertionShaped.client, RP_ID)).rejects.toThrow(
      "no attestation object",
    );
    const attestationShaped = fakeClient({ clientDataJSON: "x", attestationObject: "y" });
    await expect(assert(presenceRequest, attestationShaped.client, RP_ID)).rejects.toThrow(
      "no assertion",
    );
  });
});

describe("the presence surface probe", () => {
  const helpers = { parseCreationOptionsFromJSON: () => {}, parseRequestOptionsFromJSON: () => {} };
  test.each([
    ["no WebAuthn API at all", undefined, "software_confirmation"],
    [
      "an API without the JSON helpers the ceremony calls (Chrome before 134)",
      { isUserVerifyingPlatformAuthenticatorAvailable: async (): Promise<boolean> => true },
      "software_confirmation",
    ],
    ["an API without the platform probe", helpers, "security_key"],
    [
      "a platform authenticator present",
      {
        ...helpers,
        isUserVerifyingPlatformAuthenticatorAvailable: async (): Promise<boolean> => true,
      },
      "platform_authenticator",
    ],
    [
      "no platform authenticator",
      {
        ...helpers,
        isUserVerifyingPlatformAuthenticatorAvailable: async (): Promise<boolean> => false,
      },
      "security_key",
    ],
    [
      "a probe that throws",
      {
        ...helpers,
        isUserVerifyingPlatformAuthenticatorAvailable: async (): Promise<boolean> => {
          throw new Error("denied");
        },
      },
      "security_key",
    ],
  ] as const)("%s -> %s", async (_name, api, want) => {
    // The label the user sees comes from the page's own probe: a software confirmation must never be
    // presented as a hardware tap, a browser that cannot run the ceremony must not advertise one, and a
    // missing probe must not read as "no authenticator" when a security key could still answer.
    await expect(presenceSurface(api)).resolves.toBe(want);
  });
});
