import { beforeEach, describe, expect, it, vi } from "vitest";

// The Tauri bridges are mocked at the module boundary: these tests pin the
// echo-loop contract (ADR-0032 decision 7) - WHICH paths emit lang_set and
// which never may - so the assertions are about invoke() calls, not IPC.
const { invokeMock, listenMock } = vi.hoisted(() => ({
  invokeMock: vi.fn<(cmd: string, args?: unknown) => Promise<unknown>>(),
  listenMock: vi.fn<(event: string, handler: () => void) => Promise<() => void>>(),
}));
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/api/event", () => ({ listen: listenMock }));

import { getUiLanguage, setUiLanguage, subscribeLocale } from "../src/lib/i18n";
import {
  applyHostLanguage,
  chooseLanguage,
  initLanguageSync,
  isSharedLanguage,
  resetLanguageSyncForTests,
  syncLanguageFromHost,
} from "../src/lib/lang-sync";

const langSetCalls = () => invokeMock.mock.calls.filter(([cmd]) => cmd === "lang_set");

beforeEach(() => {
  resetLanguageSyncForTests();
  invokeMock.mockReset();
  listenMock.mockReset();
  listenMock.mockResolvedValue(() => {});
  setUiLanguage("auto");
});

describe("applyHostLanguage (the incoming path)", () => {
  it("applies a fresh host value and NEVER emits lang_set", () => {
    expect(applyHostLanguage({ value: "zh_CN", seq: 1 })).toBe(true);
    expect(getUiLanguage()).toBe("zh_CN");
    // The echo-loop rule: the apply path must not call the set command -
    // not lang_set, not anything (it is synchronous and command-free).
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("treats seq 0 as never-explicitly-set: no signal, local preference stands", () => {
    setUiLanguage("zh_TW");
    expect(applyHostLanguage({ value: "en", seq: 0 })).toBe(false);
    expect(getUiLanguage()).toBe("zh_TW");
  });

  it("applies only a seq STRICTLY greater than the last applied", () => {
    expect(applyHostLanguage({ value: "zh_CN", seq: 2 })).toBe(true);
    // A replay of the same seq, and anything older, is ignored.
    expect(applyHostLanguage({ value: "en", seq: 2 })).toBe(false);
    expect(applyHostLanguage({ value: "en", seq: 1 })).toBe(false);
    expect(getUiLanguage()).toBe("zh_CN");
    // The next genuine change applies.
    expect(applyHostLanguage({ value: "zh_TW", seq: 3 })).toBe(true);
    expect(getUiLanguage()).toBe("zh_TW");
  });

  it("refuses an out-of-enum value and keeps the current language", () => {
    setUiLanguage("en");
    expect(applyHostLanguage({ value: "fr", seq: 5 })).toBe(false);
    expect(getUiLanguage()).toBe("en");
    // The cursor did not advance on the refusal: a later valid value at the
    // same seq still applies.
    expect(applyHostLanguage({ value: "zh_TW", seq: 5 })).toBe(true);
  });
});

describe("chooseLanguage (the user-gesture path)", () => {
  it("applies locally at once and emits lang_set exactly once", async () => {
    invokeMock.mockResolvedValue({ value: "zh_TW", seq: 3 });
    chooseLanguage("zh_TW");
    // The local apply is synchronous; the set rides the serialized chain.
    expect(getUiLanguage()).toBe("zh_TW");
    await vi.waitFor(() => {
      expect(langSetCalls()).toEqual([["lang_set", { value: "zh_TW" }]]);
    });
    // The seq our own set minted suppresses the echo: the epoch notice the
    // host fires for it comes back as a no-op re-read.
    await vi.waitFor(() => {
      expect(applyHostLanguage({ value: "zh_TW", seq: 3 })).toBe(false);
    });
  });

  it("keeps the choice local when the host is unavailable", async () => {
    invokeMock.mockRejectedValue("no host in this environment");
    chooseLanguage("zh_CN");
    expect(getUiLanguage()).toBe("zh_CN");
    // Nothing to await beyond letting the rejection settle without throwing.
    await Promise.resolve();
  });

  it("re-asserts the host's truth over a stale read that raced the click", async () => {
    // The codex-found divergence: a slow startup read (old host state)
    // resolves AFTER the user clicked, overwriting the local choice; the
    // set response must then re-apply its own value, not just advance the
    // cursor, or the UI would show the stale value forever (the epoch
    // re-read arrives seq-equal and is rightly rejected).
    let resolveSet: (state: { value: string; seq: number }) => void = () => {};
    invokeMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSet = resolve as typeof resolveSet;
        }),
    );
    chooseLanguage("en");
    expect(getUiLanguage()).toBe("en");
    // Let the serialized chain issue the set (it stays pending).
    await vi.waitFor(() => {
      expect(langSetCalls()).toHaveLength(1);
    });
    // The stale startup read lands now (host state from before the click).
    expect(applyHostLanguage({ value: "zh_CN", seq: 5 })).toBe(true);
    expect(getUiLanguage()).toBe("zh_CN");
    // The set response arrives: the host's resulting state wins.
    resolveSet({ value: "en", seq: 6 });
    await vi.waitFor(() => {
      expect(getUiLanguage()).toBe("en");
    });
    // And the follow-up epoch re-read is a clean no-op, not a divergence.
    expect(applyHostLanguage({ value: "en", seq: 6 })).toBe(false);
  });

  it("serializes rapid choices so sets reach the host in click order", async () => {
    const setValues: string[] = [];
    invokeMock.mockImplementation((cmd, args) => {
      if (cmd === "lang_set") {
        const { value } = args as { value: string };
        setValues.push(value);
        return Promise.resolve({ value, seq: setValues.length });
      }
      return Promise.reject("unexpected command");
    });
    chooseLanguage("en");
    chooseLanguage("zh_TW");
    await vi.waitFor(() => {
      expect(setValues).toEqual(["en", "zh_TW"]);
    });
    expect(getUiLanguage()).toBe("zh_TW");
  });

  it("survives a throwing locale listener: the NEXT choice still reaches lang_set", async () => {
    // A locale listener that throws while the set RESPONSE re-applies (the
    // apply notifies listeners via setUiLanguage) must not poison the
    // serialized chain - a rejected chain would silently drop the next
    // click's lang_set while the UI looks right. Listener calls: (1) the
    // click's own local apply, (2) the response re-assert - throw there,
    // (3) the second click's local apply.
    let notifications = 0;
    const unsubscribe = subscribeLocale(() => {
      notifications += 1;
      if (notifications === 2) throw new Error("hostile listener");
    });
    try {
      invokeMock.mockImplementation((_cmd, args) => {
        const { value } = args as { value: string };
        return Promise.resolve({ value, seq: langSetCalls().length });
      });
      chooseLanguage("zh_CN");
      await vi.waitFor(() => {
        expect(langSetCalls()).toHaveLength(1);
      });
      // The response's re-assert threw in the listener; the chain must
      // still carry the next choice to the host.
      chooseLanguage("en");
      await vi.waitFor(() => {
        expect(langSetCalls()).toEqual([
          ["lang_set", { value: "zh_CN" }],
          ["lang_set", { value: "en" }],
        ]);
      });
      expect(getUiLanguage()).toBe("en");
    } finally {
      unsubscribe();
    }
  });
});

describe("syncLanguageFromHost + initLanguageSync", () => {
  it("pulls lang_current and applies it, still without emitting", async () => {
    invokeMock.mockResolvedValue({ value: "zh_CN", seq: 7 });
    await syncLanguageFromHost();
    expect(getUiLanguage()).toBe("zh_CN");
    expect(invokeMock).toHaveBeenCalledWith("lang_current");
    expect(langSetCalls()).toEqual([]);
  });

  it("keeps the local preference when the host store is unreadable", async () => {
    setUiLanguage("zh_TW");
    invokeMock.mockRejectedValue("the language store is unreadable");
    await syncLanguageFromHost();
    expect(getUiLanguage()).toBe("zh_TW");
  });

  it("subscribes to the lang epoch notice and re-pulls (never re-emits) on it", async () => {
    invokeMock.mockResolvedValue({ value: "en", seq: 0 });
    initLanguageSync();
    await vi.waitFor(() => {
      expect(listenMock).toHaveBeenCalledWith("lang-epoch-changed", expect.any(Function));
    });
    const initialReads = invokeMock.mock.calls.length;
    // The extension changed the language: the epoch notice arrives, the app
    // re-READS - the whole exchange stays pull-based and emit-free.
    invokeMock.mockResolvedValue({ value: "zh_TW", seq: 4 });
    const [, handler] = listenMock.mock.calls[0] as unknown as [string, () => void];
    handler();
    await vi.waitFor(() => {
      expect(getUiLanguage()).toBe("zh_TW");
    });
    expect(invokeMock.mock.calls.length).toBeGreaterThan(initialReads);
    expect(langSetCalls()).toEqual([]);
  });
});

describe("isSharedLanguage", () => {
  it("accepts exactly the shared uiLanguage enum", () => {
    for (const ok of ["auto", "en", "zh_CN", "zh_TW"]) {
      expect(isSharedLanguage(ok)).toBe(true);
    }
    for (const bad of ["fr", "EN", "zh", "", "en_US"]) {
      expect(isSharedLanguage(bad)).toBe(false);
    }
  });
});
