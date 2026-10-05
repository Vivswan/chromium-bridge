#!/usr/bin/env bun
// A stand-in native host for cancel_test.ts. Chrome spawns it from the throwaway profile's host manifest
// (through a two-line exec wrapper the test writes), so it speaks Chrome's native-messaging framing on stdio
// like the real host: a 4-byte little-endian length prefix, then UTF-8 JSON.
//
// It plays one fixed script and records what the extension sends back, one JSON line per inbound frame, into
// the log file named by argv[2]; the test reads that file. No real host, no MCP server, no session is involved.
//
//   first inbound frame (the SW's connect-time kill_status)  -> send cancel { id: 41 }, then the tab_list
//                                                               request { id: 42 }
//   stdin EOF (Chrome closed the port)                       -> exit

import { appendFileSync } from "node:fs";

function usage(): never {
  console.error("usage: fake_host.ts <log-file>");
  process.exit(2);
}

const logFile: string = process.argv[2] ?? usage();

function send(frame: object): void {
  const body = Buffer.from(JSON.stringify(frame), "utf8");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  process.stdout.write(Buffer.concat([header, body]));
}

let scripted = false;
function onFrame(frame: unknown): void {
  appendFileSync(logFile, `${JSON.stringify(frame)}\n`);
  if (scripted) return;
  scripted = true;
  send({ type: "cancel", id: 41 });
  send({ id: 42, op: "tab_list", args: {} });
}

// Frames arrive in arbitrary chunking; the length prefix says where each one ends.
let pending = Buffer.alloc(0);
for await (const chunk of Bun.stdin.stream()) {
  pending = Buffer.concat([pending, Buffer.from(chunk)]);
  while (pending.length >= 4) {
    const length = pending.readUInt32LE(0);
    if (pending.length < 4 + length) break;
    const body = pending.subarray(4, 4 + length).toString("utf8");
    pending = pending.subarray(4 + length);
    onFrame(JSON.parse(body));
  }
}
