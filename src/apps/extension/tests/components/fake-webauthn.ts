import { vi } from "vitest";

// Chrome's WebAuthn client, stood in for under happy-dom: `PublicKeyCredential` with the JSON helpers the
// ceremony calls (identity, since the page already speaks the JSON spellings) and `navigator.credentials`
// answering with whatever credential JSON the test hands it. Every call is recorded so a test can pin the
// options the page built from the host's frame.
export interface FakeWebAuthn {
  calls: { create: unknown[]; get: unknown[] };
  /** What `create` answers (or throws); the test sets it per case. */
  createResponse: () => RegistrationResponseJSON;
  /** What `get` answers (or throws). */
  getResponse: () => AuthenticationResponseJSON;
}

export function installFakeWebAuthn(): FakeWebAuthn {
  const fake: FakeWebAuthn = {
    calls: { create: [], get: [] },
    createResponse: () => {
      throw new Error("the test set no create response");
    },
    getResponse: () => {
      throw new Error("the test set no get response");
    },
  };
  class FakePublicKeyCredential {
    constructor(private readonly json: unknown) {}
    toJSON(): unknown {
      return this.json;
    }
    static parseCreationOptionsFromJSON(options: unknown): unknown {
      return options;
    }
    static parseRequestOptionsFromJSON(options: unknown): unknown {
      return options;
    }
    static isUserVerifyingPlatformAuthenticatorAvailable(): Promise<boolean> {
      return Promise.resolve(true);
    }
  }
  vi.stubGlobal("PublicKeyCredential", FakePublicKeyCredential);
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: {
      async create({ publicKey }: { publicKey: unknown }) {
        fake.calls.create.push(publicKey);
        return new FakePublicKeyCredential(fake.createResponse());
      },
      async get({ publicKey }: { publicKey: unknown }) {
        fake.calls.get.push(publicKey);
        return new FakePublicKeyCredential(fake.getResponse());
      },
    },
  });
  return fake;
}

/** A registration response JSON, as Chrome's `toJSON()` spells it. */
export function createdCredential(rawId: string): RegistrationResponseJSON {
  return {
    id: rawId,
    rawId,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response: {
      clientDataJSON: "Y2xpZW50LWRhdGEtY3JlYXRl",
      attestationObject: "YXR0ZXN0YXRpb24",
      authenticatorData: "YXV0aC1kYXRh",
      publicKeyAlgorithm: -7,
      transports: ["internal"],
    },
  };
}

/** An assertion response JSON for credential `rawId`. */
export function assertedCredential(rawId: string): AuthenticationResponseJSON {
  return {
    id: rawId,
    rawId,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response: {
      clientDataJSON: "Y2xpZW50LWRhdGEtZ2V0",
      authenticatorData: "YXV0aC1kYXRh",
      signature: "c2lnbmF0dXJl",
    },
  };
}
