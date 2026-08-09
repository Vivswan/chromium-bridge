#!/usr/bin/env bun

// Deterministic local fake LLM backend for the live tool-call probes in
// tests/harness/run.ts: real harness CLIs (claude -p, codex exec) are pointed
// here via their base-URL overrides, so a FULL model-driven MCP tool call
// runs with zero credentials and zero model spend. The playback-scenario +
// /_test introspection-route pattern follows the litellm-vscode-chat fake
// stack; the code is written fresh for this repo.
//
// The scenario is content-addressed, not turn-counted, so it stays
// deterministic across harness retries and auxiliary model calls (topic
// detection, title generation, token counting):
//
//   1. a request whose messages carry a TOOL RESULT gets plain final text
//      (ending the agent run);
//   2. otherwise, a request advertising the bridge's tab_list tool gets a
//      tool call invoking it (the exact advertised name) with {} arguments;
//   3. anything else gets a trivial text reply.
//
// Routes:
//   POST /v1/messages                Anthropic Messages API (Claude Code)
//   POST /v1/messages/count_tokens   fixed count (aux)
//   GET  /v1/models                  minimal model list (aux)
//   POST /v1/responses               OpenAI Responses API (codex; its 0.146+
//                                    config refuses wire_api "chat" outright)
//   POST /v1/chat/completions        OpenAI Chat Completions (generic clients)
//   GET  /health                     liveness
//   GET  /_test/requests             every recorded request, for the driver's asserts
//
// Unknown routes are recorded too (and answer 404): a harness release that
// starts probing a new endpoint shows up in /_test/requests instead of
// vanishing. Binds 127.0.0.1 on an ephemeral port; --portfile <path> writes
// the bound port for the driver. Node builtins only, like run.ts: the suite
// must run without a `bun install`.

import { renameSync, writeFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import http from "node:http";

const usage = "usage: bun tests/harness/fake-llm.ts [--portfile <path>]";

/** The tool the scenario drives (its bridge-side name; harnesses advertise
 * it to the model under a harness-specific prefixed name). */
const BRIDGE_TOOL = "tab_list";

/** The invocation ids the scenario issues (one per wire shape). The driver
 * asserts the returned tool result echoes one of them, tying turn 2 to OUR
 * call rather than to any result that happens to carry the right text. */
export const ANTHROPIC_TOOL_USE_ID = "toolu_fakellm_1";
export const OPENAI_CALL_ID = "call_fakellm_1";

/** Bounds on the in-memory recording: past MAX_RECORDED the server keeps
 * answering normally but only counts the overflow (served as `dropped`),
 * and past the total body budget it records classification fields with a
 * dropped-body marker - a runaway harness loop degrades the introspection
 * instead of the process. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_RECORDED = 200;
const TOTAL_BODY_BUDGET_BYTES = 32 * 1024 * 1024;

/** Hard lifetime bound. The driver kills this process, but when the driver
 * itself dies uncleanly (CI job timeout is a SIGKILL) nothing else would;
 * self-terminating comfortably past the driver's probe timeout also makes
 * manual runs self-cleaning. Exported so the driver can enforce that its
 * probe timeout stays below it. */
export const MAX_LIFETIME_MS = 300_000;

interface RecordedBase {
  route: string;
  /** Every tool name the request advertised (empty when it carried none). */
  toolNames: string[];
  body: unknown;
}

/** One recorded request, served back by GET /_test/requests. The kind is
 * the discriminant: a turn-1 record always carries the invoked tool name, a
 * turn-2 record always carries the tool-result text and the invocation id
 * the result echoed ("" when the harness omitted one). */
export type RecordedRequest =
  | (RecordedBase & { kind: "turn1-tool-call"; invokedTool: string })
  | (RecordedBase & { kind: "turn2-final"; toolResultText: string; toolResultId: string })
  | (RecordedBase & { kind: "aux" | "other" });

const requests: RecordedRequest[] = [];
let droppedRequests = 0;
let recordedBodyBytes = 0;

function record(entry: RecordedRequest): void {
  if (requests.length >= MAX_RECORDED) {
    droppedRequests += 1;
    return;
  }
  const bytes =
    entry.body === undefined ? 0 : Buffer.byteLength(JSON.stringify(entry.body) ?? "", "utf8");
  if (recordedBodyBytes + bytes > TOTAL_BODY_BUDGET_BYTES) {
    requests.push({ ...entry, body: "(body dropped: recording budget exhausted)" });
    return;
  }
  recordedBodyBytes += bytes;
  requests.push(entry);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

/** One SSE event per entry; `event:` line omitted for nameless streams
 * (OpenAI chunks are data-only, Anthropic events are named). */
function sendSse(res: ServerResponse, events: { event?: string; data: string }[]): void {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  for (const { event, data } of events) {
    if (event !== undefined) res.write(`event: ${event}\n`);
    res.write(`data: ${data}\n\n`);
  }
  res.end();
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    req.setEncoding("utf8");
    let data = "";
    let overflowed = false;
    req.on("data", (chunk: string) => {
      if (overflowed) return;
      data += chunk;
      if (Buffer.byteLength(data, "utf8") > maxBytes) {
        overflowed = true;
        resolve(undefined);
      }
    });
    req.on("end", () => {
      if (!overflowed) resolve(data);
    });
    req.on("error", reject);
  });
}

/** Flatten a tool-result content value (string, or a list of text blocks)
 * into the text the driver asserts against. */
function flattenText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((item) => {
        const text = (item as { text?: unknown } | null)?.text;
        return typeof text === "string" ? text : "";
      })
      .filter((text) => text !== "")
      .join("\n");
  }
  return JSON.stringify(content) ?? "";
}

/** The advertised name the scenario invokes: the first tool that IS the
 * bridge tool under whatever prefix the harness applied (claude:
 * mcp__<server>__tab_list; codex namespaces: mcp__<server>.tab_list; a bare
 * tab_list also counts). */
function findBridgeTool(toolNames: string[]): string | undefined {
  return toolNames.find(
    (name) =>
      name === BRIDGE_TOOL || name.endsWith(`__${BRIDGE_TOOL}`) || name.endsWith(`.${BRIDGE_TOOL}`),
  );
}

// ---------------------------------------------------------------------------
// Anthropic Messages API (Claude Code)
// ---------------------------------------------------------------------------

interface AnthropicBody {
  stream?: unknown;
  tools?: unknown;
  messages?: unknown;
}

function anthropicToolNames(body: AnthropicBody): string[] {
  if (!Array.isArray(body.tools)) return [];
  return body.tools
    .map((tool) => (tool as { name?: unknown } | null)?.name)
    .filter((name): name is string => typeof name === "string");
}

/** A tool result found in a request's messages: its flattened text plus
 * the invocation id it echoes ("" when the harness omitted one). */
interface ToolResult {
  text: string;
  id: string;
}

function anthropicToolResult(body: AnthropicBody): ToolResult | undefined {
  if (!Array.isArray(body.messages)) return undefined;
  for (const message of body.messages) {
    const content = (message as { content?: unknown } | null)?.content;
    if (!Array.isArray(content)) continue;
    for (const item of content) {
      // biome-ignore lint/style/useNamingConvention: tool_use_id is the Anthropic wire field
      const block = item as { type?: unknown; content?: unknown; tool_use_id?: unknown } | null;
      if (block?.type === "tool_result") {
        return {
          text: flattenText(block.content),
          id: typeof block.tool_use_id === "string" ? block.tool_use_id : "",
        };
      }
    }
  }
  return undefined;
}

/** A complete assistant message both as the non-streaming body and as the
 * event list the streaming path plays (Anthropic delta framing). */
function anthropicReply(
  res: ServerResponse,
  stream: boolean,
  block: Record<string, unknown>,
  delta: { event: string; data: string } | undefined,
  stopReason: string,
): void {
  if (!stream) {
    sendJson(res, 200, {
      id: "msg_fakellm",
      type: "message",
      role: "assistant",
      model: "fake-llm",
      content: [block],
      stop_reason: stopReason,
      stop_sequence: null,
      usage: { input_tokens: 1, output_tokens: 1 },
    });
    return;
  }
  const startBlock = block.type === "tool_use" ? { ...block, input: {} } : { ...block, text: "" };
  const events = [
    {
      event: "message_start",
      data: JSON.stringify({
        type: "message_start",
        message: {
          id: "msg_fakellm",
          type: "message",
          role: "assistant",
          model: "fake-llm",
          content: [],
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 1, output_tokens: 1 },
        },
      }),
    },
    {
      event: "content_block_start",
      data: JSON.stringify({ type: "content_block_start", index: 0, content_block: startBlock }),
    },
    ...(delta === undefined ? [] : [delta]),
    {
      event: "content_block_stop",
      data: JSON.stringify({ type: "content_block_stop", index: 0 }),
    },
    {
      event: "message_delta",
      data: JSON.stringify({
        type: "message_delta",
        delta: { stop_reason: stopReason, stop_sequence: null },
        usage: { output_tokens: 1 },
      }),
    },
    { event: "message_stop", data: JSON.stringify({ type: "message_stop" }) },
  ];
  sendSse(res, events);
}

function handleAnthropicMessages(res: ServerResponse, body: AnthropicBody): void {
  const stream = body.stream === true;
  const toolNames = anthropicToolNames(body);
  const toolResult = anthropicToolResult(body);
  if (toolResult !== undefined) {
    record({
      route: "/v1/messages",
      kind: "turn2-final",
      toolNames,
      toolResultText: toolResult.text,
      toolResultId: toolResult.id,
      body,
    });
    anthropicReply(
      res,
      stream,
      { type: "text", text: "The tab_list call returned; ending the run." },
      {
        event: "content_block_delta",
        data: JSON.stringify({
          type: "content_block_delta",
          index: 0,
          delta: { type: "text_delta", text: "The tab_list call returned; ending the run." },
        }),
      },
      "end_turn",
    );
    return;
  }
  const invokedTool = findBridgeTool(toolNames);
  if (invokedTool !== undefined) {
    record({ route: "/v1/messages", kind: "turn1-tool-call", toolNames, invokedTool, body });
    anthropicReply(
      res,
      stream,
      { type: "tool_use", id: ANTHROPIC_TOOL_USE_ID, name: invokedTool, input: {} },
      {
        event: "content_block_delta",
        data: JSON.stringify({
          type: "content_block_delta",
          index: 0,
          delta: { type: "input_json_delta", partial_json: "{}" },
        }),
      },
      "tool_use",
    );
    return;
  }
  record({ route: "/v1/messages", kind: "aux", toolNames, body });
  anthropicReply(
    res,
    stream,
    { type: "text", text: "ok" },
    {
      event: "content_block_delta",
      data: JSON.stringify({
        type: "content_block_delta",
        index: 0,
        delta: { type: "text_delta", text: "ok" },
      }),
    },
    "end_turn",
  );
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions (codex, wire_api "chat")
// ---------------------------------------------------------------------------

interface OpenAiBody {
  stream?: unknown;
  tools?: unknown;
  messages?: unknown;
}

function openaiToolNames(body: OpenAiBody): string[] {
  if (!Array.isArray(body.tools)) return [];
  return body.tools
    .map((tool) => (tool as { function?: { name?: unknown } } | null)?.function?.name)
    .filter((name): name is string => typeof name === "string");
}

function openaiToolResult(body: OpenAiBody): ToolResult | undefined {
  if (!Array.isArray(body.messages)) return undefined;
  for (const message of body.messages) {
    const entry = message as {
      role?: unknown;
      content?: unknown;
      // biome-ignore lint/style/useNamingConvention: tool_call_id is the OpenAI wire field
      tool_call_id?: unknown;
    } | null;
    if (entry?.role === "tool") {
      return {
        text: flattenText(entry.content),
        id: typeof entry.tool_call_id === "string" ? entry.tool_call_id : "",
      };
    }
  }
  return undefined;
}

function openaiReply(
  res: ServerResponse,
  stream: boolean,
  message: Record<string, unknown>,
  finishReason: string,
): void {
  if (!stream) {
    sendJson(res, 200, {
      id: "chatcmpl-fakellm",
      object: "chat.completion",
      created: 0,
      model: "fake-llm",
      choices: [
        { index: 0, message: { role: "assistant", ...message }, finish_reason: finishReason },
      ],
      usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
    });
    return;
  }
  const chunk = (delta: Record<string, unknown>, finish: string | null): string =>
    JSON.stringify({
      id: "chatcmpl-fakellm",
      object: "chat.completion.chunk",
      created: 0,
      model: "fake-llm",
      choices: [{ index: 0, delta, finish_reason: finish }],
    });
  sendSse(res, [
    { data: chunk({ role: "assistant", ...message }, null) },
    { data: chunk({}, finishReason) },
    { data: "[DONE]" },
  ]);
}

function handleChatCompletions(res: ServerResponse, body: OpenAiBody): void {
  const stream = body.stream === true;
  const toolNames = openaiToolNames(body);
  const toolResult = openaiToolResult(body);
  if (toolResult !== undefined) {
    record({
      route: "/v1/chat/completions",
      kind: "turn2-final",
      toolNames,
      toolResultText: toolResult.text,
      toolResultId: toolResult.id,
      body,
    });
    openaiReply(res, stream, { content: "The tab_list call returned; ending the run." }, "stop");
    return;
  }
  const invokedTool = findBridgeTool(toolNames);
  if (invokedTool !== undefined) {
    record({
      route: "/v1/chat/completions",
      kind: "turn1-tool-call",
      toolNames,
      invokedTool,
      body,
    });
    openaiReply(
      res,
      stream,
      {
        content: null,
        tool_calls: [
          {
            index: 0,
            id: OPENAI_CALL_ID,
            type: "function",
            function: { name: invokedTool, arguments: "{}" },
          },
        ],
      },
      "tool_calls",
    );
    return;
  }
  record({ route: "/v1/chat/completions", kind: "aux", toolNames, body });
  openaiReply(res, stream, { content: "ok" }, "stop");
}

// ---------------------------------------------------------------------------
// OpenAI Responses API (codex)
// ---------------------------------------------------------------------------

interface ResponsesBody {
  tools?: unknown;
  input?: unknown;
}

/** Flat function tools by name; namespace tools (codex 0.146+ groups each
 * MCP server under one) contribute their members as <namespace>.<member>.
 * The dotted form is for recording/matching only - invocation carries the
 * namespace as its own function_call field (see handleResponses). */
function responsesToolNames(body: ResponsesBody): string[] {
  if (!Array.isArray(body.tools)) return [];
  const names: string[] = [];
  for (const entry of body.tools) {
    const tool = entry as { type?: unknown; name?: unknown; tools?: unknown } | null;
    if (typeof tool?.name !== "string") continue;
    if (tool.type === "namespace" && Array.isArray(tool.tools)) {
      for (const member of tool.tools) {
        const name = (member as { name?: unknown } | null)?.name;
        if (typeof name === "string") names.push(`${tool.name}.${name}`);
      }
    } else {
      names.push(tool.name);
    }
  }
  return names;
}

function responsesToolResult(body: ResponsesBody): ToolResult | undefined {
  if (!Array.isArray(body.input)) return undefined;
  for (const item of body.input) {
    // biome-ignore lint/style/useNamingConvention: call_id is the OpenAI wire field
    const entry = item as { type?: unknown; output?: unknown; call_id?: unknown } | null;
    if (entry?.type !== "function_call_output" && entry?.type !== "custom_tool_call_output") {
      continue;
    }
    return {
      text: typeof entry.output === "string" ? entry.output : flattenText(entry.output),
      id: typeof entry.call_id === "string" ? entry.call_id : "",
    };
  }
  return undefined;
}

/** Codex always streams; the minimal event sequence its client needs is
 * response.created, one response.output_item.done per item, and a
 * response.completed carrying the full output plus usage. */
function responsesReply(res: ServerResponse, item: Record<string, unknown>): void {
  const usage = {
    input_tokens: 1,
    input_tokens_details: { cached_tokens: 0 },
    output_tokens: 1,
    output_tokens_details: { reasoning_tokens: 0 },
    total_tokens: 2,
  };
  sendSse(res, [
    {
      event: "response.created",
      data: JSON.stringify({ type: "response.created", response: { id: "resp_fakellm" } }),
    },
    {
      event: "response.output_item.done",
      data: JSON.stringify({ type: "response.output_item.done", output_index: 0, item }),
    },
    {
      event: "response.completed",
      data: JSON.stringify({
        type: "response.completed",
        response: { id: "resp_fakellm", usage, output: [item] },
      }),
    },
  ]);
}

function responsesTextItem(text: string): Record<string, unknown> {
  return {
    type: "message",
    id: "msg_fakellm_out",
    role: "assistant",
    content: [{ type: "output_text", text }],
  };
}

function handleResponses(res: ServerResponse, body: ResponsesBody): void {
  const toolNames = responsesToolNames(body);
  const toolResult = responsesToolResult(body);
  if (toolResult !== undefined) {
    record({
      route: "/v1/responses",
      kind: "turn2-final",
      toolNames,
      toolResultText: toolResult.text,
      toolResultId: toolResult.id,
      body,
    });
    responsesReply(res, responsesTextItem("The tab_list call returned; ending the run."));
    return;
  }
  const invokedTool = findBridgeTool(toolNames);
  if (invokedTool !== undefined) {
    record({ route: "/v1/responses", kind: "turn1-tool-call", toolNames, invokedTool, body });
    // A namespaced member (the dotted recording form) is invoked with the
    // namespace as its OWN field - codex's registry looks tools up by the
    // (namespace, name) pair and rejects flattened spellings. Split on the
    // LAST dot: the namespace may contain dots, the matched member
    // (tab_list) does not.
    const dot = invokedTool.lastIndexOf(".");
    const routing =
      dot === -1
        ? { name: invokedTool }
        : { namespace: invokedTool.slice(0, dot), name: invokedTool.slice(dot + 1) };
    responsesReply(res, {
      type: "function_call",
      id: "fc_fakellm_1",
      call_id: OPENAI_CALL_ID,
      ...routing,
      arguments: "{}",
    });
    return;
  }
  record({ route: "/v1/responses", kind: "aux", toolNames, body });
  responsesReply(res, responsesTextItem("ok"));
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const pathname = new URL(req.url ?? "/", "http://127.0.0.1").pathname;

  if (req.method === "GET" && pathname === "/health") {
    return sendJson(res, 200, { status: "ok" });
  }
  if (req.method === "GET" && pathname === "/_test/requests") {
    return sendJson(res, 200, { requests, dropped: droppedRequests });
  }
  if (req.method === "GET" && pathname === "/v1/models") {
    record({ route: pathname, kind: "aux", toolNames: [], body: undefined });
    return sendJson(res, 200, {
      object: "list",
      data: [{ id: "fake-llm", object: "model", created: 0, owned_by: "fake-llm" }],
    });
  }

  if (req.method === "POST") {
    const raw = await readBody(req, MAX_BODY_BYTES);
    if (raw === undefined) {
      req.resume();
      return sendJson(res, 413, { error: { message: "Request body exceeds the recording cap" } });
    }
    let body: Record<string, unknown>;
    try {
      const parsed: unknown = raw === "" ? {} : JSON.parse(raw);
      body =
        typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : {};
    } catch {
      record({ route: pathname, kind: "other", toolNames: [], body: raw });
      return sendJson(res, 400, { error: { message: "Invalid JSON" } });
    }
    if (pathname === "/v1/messages") return handleAnthropicMessages(res, body);
    if (pathname === "/v1/messages/count_tokens") {
      record({ route: pathname, kind: "aux", toolNames: [], body });
      return sendJson(res, 200, { input_tokens: 128 });
    }
    if (pathname === "/v1/responses") return handleResponses(res, body);
    if (pathname === "/v1/chat/completions") return handleChatCompletions(res, body);
    record({ route: pathname, kind: "other", toolNames: [], body });
    return sendJson(res, 404, { error: { message: `No route for ${pathname}` } });
  }

  record({ route: pathname, kind: "other", toolNames: [], body: undefined });
  sendJson(res, 404, { error: { message: `No route for ${pathname}` } });
}

function main(): void {
  let portfile: string | undefined;
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--portfile" && argv[i + 1] !== undefined) {
      portfile = argv[i + 1];
      i += 1;
    } else {
      console.error(`error: invalid argument: ${argv[i]}\n${usage}`);
      process.exit(2);
    }
  }
  const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(() => {
      // A failed handler must not hang the connection open.
      res.destroy();
    });
  });
  // 127.0.0.1 only, ephemeral port: nothing off-machine can reach this, and
  // parallel runs cannot collide.
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    const port = typeof address === "object" && address !== null ? address.port : 0;
    console.log(`[fake-llm] listening on 127.0.0.1:${port}`);
    if (portfile !== undefined) {
      // Write-then-rename so the driver's existence poll can never observe
      // a half-written port.
      writeFileSync(`${portfile}.tmp`, `${port}\n`);
      renameSync(`${portfile}.tmp`, portfile);
    }
  });
  setTimeout(() => {
    console.error(`[fake-llm] lifetime bound (${MAX_LIFETIME_MS}ms) reached; exiting`);
    process.exit(0);
  }, MAX_LIFETIME_MS);
}

if (import.meta.main) {
  main();
}
