// Named incident: CI checks runs 37163429917 and 37163904223. connect read
// /json/list once, before headless Chrome listed its initial tab. A fake
// /json/list stands in for Chrome; no browser is launched.

import { afterEach, describe, expect, test } from "bun:test";
import { type DevToolsTarget, waitForPageTarget } from "./devtools-target";

const PAGE: DevToolsTarget = { id: "7A1B", type: "page" };
const WORKERS: DevToolsTarget[] = [
  { id: "SW1", type: "service_worker" },
  { id: "BG1", type: "background_page" },
];

function fakeDevTools(listFor: (call: number) => DevToolsTarget[] | undefined) {
  let calls = 0;
  const server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req) {
      if (new URL(req.url).pathname !== "/json/list") return new Response("", { status: 404 });
      calls++;
      const list = listFor(calls);
      return list === undefined ? new Promise<Response>(() => {}) : Response.json(list);
    },
  });
  return {
    port: server.port as number,
    calls: () => calls,
    stop: () => server.stop(true),
  };
}

describe("waitForPageTarget", () => {
  let server: ReturnType<typeof fakeDevTools> | undefined;
  afterEach(() => {
    server?.stop();
    server = undefined;
  });

  test("connects once the page target is listed, however many empty lists come first", async () => {
    server = fakeDevTools((call) => (call <= 3 ? [] : [PAGE]));
    await expect(waitForPageTarget(server.port, 10_000)).resolves.toEqual(PAGE);
    expect(server.calls()).toBe(4);
  });

  const deadlineCases: [name: string, listFor: () => DevToolsTarget[] | undefined, seen: string][] =
    [
      [
        "a list that never holds a page",
        () => WORKERS,
        String.raw`\d+ polls of /json/list; last listed types: \[service_worker, background_page\]`,
      ],
      ["an endpoint that never answers", () => undefined, "/json/list never answered"],
    ];
  test.each(deadlineCases)(
    "%s fails at the deadline saying what was seen",
    async (_name, listFor, seen) => {
      server = fakeDevTools(listFor);
      await expect(waitForPageTarget(server.port, 350)).rejects.toThrow(
        new RegExp(`^no DevTools page target on port ${server.port} within 350ms \\(${seen}\\)$`),
      );
    },
  );
});
