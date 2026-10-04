// send() is the one place the pages trust the service worker's answer. A
// transport failure or an answer outside the contract must become the
// declared refusal arm, never a view rendering a shape it assumed; the
// declared answer passes through unchanged.

import { describe, expect, test, vi } from "vitest";
import { fakeBrowser } from "wxt/testing/fake-browser";
import { send } from "@/lib/messages";

describe("send() parses every answer against the contract", () => {
  test.each([
    {
      name: "the worker is unreachable",
      reply: () => Promise.reject(new Error("Could not establish connection")),
      expected: { ok: false, error: "no answer from the service worker" },
    },
    {
      name: "the answer lacks the declared discriminant",
      reply: () => Promise.resolve({ list: ["https://a.example/*"] }),
      expected: { ok: false, error: "malformed get_allowlist response from the service worker" },
    },
    {
      name: "the answer is the declared shape",
      reply: () => Promise.resolve({ ok: true, list: ["https://a.example/*"] }),
      expected: { ok: true, list: ["https://a.example/*"] },
    },
    {
      name: "the answer is the worker's refusal",
      reply: () => Promise.resolve({ ok: false, error: "malformed runtime message" }),
      expected: { ok: false, error: "malformed runtime message" },
    },
  ])("$name", async ({ reply, expected }) => {
    vi.spyOn(fakeBrowser.runtime, "sendMessage").mockImplementation(reply);
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(send({ type: "get_allowlist" })).resolves.toEqual(expected);
  });
});
