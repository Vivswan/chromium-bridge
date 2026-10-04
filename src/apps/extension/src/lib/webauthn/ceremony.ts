// The page half of the WebAuthn ceremonies: the feature probe, and `navigator.credentials.create` / `.get`
// with RP ID = this extension's id, each shaped from the host's frame and shaped back into the frame the
// worker posts (exchange.ts). Runs in an extension page (the options page), never in the service worker,
// which has no `navigator.credentials`.
//
// The host decides everything cryptographic (challenge, allowed credentials, verification) and the page
// adds only what the API needs: ES256 alone, attestation "none", no extensions.

import type {
  EnrollOptionsFrame,
  PresenceRequestFrame,
} from "@chromium-bridge/shared/envelope.gen";
import type {
  AssertionResponse,
  PresenceSurface,
  RegistrationResponse,
} from "@chromium-bridge/shared/webauthn";
import { browser } from "wxt/browser";

/** The two WebAuthn calls, in their JSON spellings, so a test can stand in for the browser. The browser
 * client below maps them onto `PublicKeyCredential.parse*FromJSON` and `toJSON()`. */
export interface WebAuthnClient {
  create(options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON>;
  get(options: PublicKeyCredentialRequestOptionsJSON): Promise<AuthenticationResponseJSON>;
}

/** The static side of `PublicKeyCredential` the probe reads; injectable so the probe is unit-testable
 * without a browser. `undefined` is a browser with no WebAuthn API at all. The JSON helpers are the ones
 * register/assert call: a browser without them cannot run this ceremony however able its authenticator. */
export interface PlatformProbe {
  isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
  parseCreationOptionsFromJSON?: unknown;
  parseRequestOptionsFromJSON?: unknown;
}

/** The display name the authenticator shows for this RP and user; the host's `user_name` is the browser label. */
export const RP_NAME = "Chromium Bridge";

/** The COSE algorithm the host verifies: ES256. The only entry in pubKeyCredParams, so an authenticator
 * that cannot do it fails the ceremony instead of minting a key the host would refuse at enroll_finish. */
export const ES256 = -7;

/** How long the authenticator prompt stays up before the ceremony fails closed. */
export const CEREMONY_TIMEOUT_MS = 120_000;

/** Which surface a tap would land on. A software confirmation is the honest label when the browser cannot
 * run the ceremony (no WebAuthn API, or one without the JSON helpers); an API without a user-verifying
 * platform authenticator may still reach a security key. */
export async function presenceSurface(
  api: PlatformProbe | undefined = globalThis.PublicKeyCredential,
): Promise<PresenceSurface> {
  if (!api?.parseCreationOptionsFromJSON || !api.parseRequestOptionsFromJSON) {
    return "software_confirmation";
  }
  const probe = api.isUserVerifyingPlatformAuthenticatorAvailable;
  if (!probe) return "security_key";
  try {
    return (await probe.call(api)) ? "platform_authenticator" : "security_key";
  } catch {
    return "security_key";
  }
}

/** The creation options the page hands the authenticator for the host's enroll_options. */
export function creationOptions(
  options: EnrollOptionsFrame,
  rpId: string,
): PublicKeyCredentialCreationOptionsJSON {
  return {
    rp: { id: rpId, name: RP_NAME },
    user: { id: options.user_id, name: options.user_name, displayName: options.user_name },
    challenge: options.challenge,
    pubKeyCredParams: [{ type: "public-key", alg: ES256 }],
    excludeCredentials: options.exclude_credential_ids.map((id) => ({ type: "public-key", id })),
    authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
    attestation: "none",
    timeout: CEREMONY_TIMEOUT_MS,
  };
}

/** The request options the page hands the authenticator for the host's presence_request. */
export function requestOptions(
  request: PresenceRequestFrame,
  rpId: string,
): PublicKeyCredentialRequestOptionsJSON {
  return {
    rpId,
    challenge: request.challenge,
    allowCredentials: request.allowed_credential_ids.map((id) => ({ type: "public-key", id })),
    userVerification: "preferred",
    timeout: CEREMONY_TIMEOUT_MS,
  };
}

/** Run `navigator.credentials.create` for the host's options and shape the response for enroll_finish.
 * Throws when the browser returns no credential (the user dismissed the prompt, or no authenticator). */
export async function register(
  options: EnrollOptionsFrame,
  client: WebAuthnClient = browserClient(),
  rpId: string = browser.runtime.id,
): Promise<RegistrationResponse> {
  const credential = await client.create(creationOptions(options, rpId));
  const { attestationObject, clientDataJSON } = credential.response;
  // The JSON types say every field is present; a browser quirk or a fake that answers with the other
  // ceremony's shape must fail here, not reach the host as a frame with undefined fields.
  if (typeof attestationObject !== "string" || typeof clientDataJSON !== "string") {
    throw new Error("the authenticator returned no attestation object");
  }
  return { attestation_object: attestationObject, client_data_json: clientDataJSON };
}

/** Run `navigator.credentials.get` for the host's request and shape the response for presence_assert. */
export async function assert(
  request: PresenceRequestFrame,
  client: WebAuthnClient = browserClient(),
  rpId: string = browser.runtime.id,
): Promise<AssertionResponse> {
  const credential = await client.get(requestOptions(request, rpId));
  const { authenticatorData, clientDataJSON, signature } = credential.response;
  if (
    typeof authenticatorData !== "string" ||
    typeof clientDataJSON !== "string" ||
    typeof signature !== "string"
  ) {
    throw new Error("the authenticator returned no assertion");
  }
  return {
    credential_id: credential.rawId,
    authenticator_data: authenticatorData,
    client_data_json: clientDataJSON,
    signature,
  };
}

/** The real browser: the JSON helpers Chrome ships, over `navigator.credentials`. */
export function browserClient(): WebAuthnClient {
  const credential = (value: Credential | null) => {
    if (!(value instanceof PublicKeyCredential)) {
      throw new Error("the browser returned no public-key credential");
    }
    return value.toJSON();
  };
  return {
    async create(options) {
      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options);
      // toJSON() is typed as either ceremony's response; create only ever yields the registration one.
      return credential(
        await navigator.credentials.create({ publicKey }),
      ) as RegistrationResponseJSON;
    },
    async get(options) {
      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options);
      return credential(
        await navigator.credentials.get({ publicKey }),
      ) as AuthenticationResponseJSON;
    },
  };
}
