import { describe, expect, test } from "vitest";
import {
  globToPermissionPattern,
  hostFromOriginGlob,
  matchesAny,
  normalizeCookieDomain,
  originGlobOf,
  simpleMatch,
} from "@/lib/shared/allowlist";

describe("simpleMatch", () => {
  test.each([
    ["an exact pattern", "https://a.com/x", "https://a.com/x", true],
    ["a trailing /* matches the base", "https://a.com/*", "https://a.com/", true],
    ["a trailing /* matches a sub-path", "https://a.com/*", "https://a.com/page", true],
    ["a trailing /* does not match another host", "https://a.com/*", "https://b.com/", false],
    ["a bare trailing * is a prefix match", "https://a.com*", "https://a.com/anything", true],
  ])("%s", (_case, pattern, target, expected) => {
    expect(simpleMatch(pattern, target)).toBe(expected);
  });
});

describe("matchesAny", () => {
  test("true if any pattern matches", () => {
    expect(matchesAny("https://a.com/x", ["https://b.com/*", "https://a.com/*"])).toBe(true);
    expect(matchesAny("https://c.com/x", ["https://a.com/*"])).toBe(false);
  });
});

describe("originGlobOf", () => {
  test.each([
    ["a URL with a path and query", "https://x.com/path?q=1", "https://x.com/*"],
    ["an unparsable string", "not a url", null],
    ["undefined", undefined, null],
  ])("%s", (_case, input, expected) => {
    expect(originGlobOf(input)).toBe(expected);
  });
});

describe("hostFromOriginGlob", () => {
  test("extracts the lowercase host", () => {
    expect(hostFromOriginGlob("https://X.COM/*")).toBe("x.com");
  });
});

describe("normalizeCookieDomain", () => {
  test.each([
    ["leading dots stripped and lowercased", ".Example.com", "example.com"],
    ["a scheme", "http://x.com", null],
    ["a path", "a/b", null],
    ["a glob", "*.x.com", null],
    ["a non-string", 123, null],
  ])("%s", (_case, input, expected) => {
    expect(normalizeCookieDomain(input)).toBe(expected);
  });
});

describe("globToPermissionPattern", () => {
  test.each([
    ["a /* glob is kept", "https://a.com/*", "https://a.com/*"],
    ["a bare origin gets a trailing *", "https://a.com", "https://a.com*"],
    ["an empty string", "", null],
  ])("%s", (_case, input, expected) => {
    expect(globToPermissionPattern(input)).toBe(expected);
  });
});
