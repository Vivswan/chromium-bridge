// @actions/core writes every step output as GitHub's heredoc record (`name<<delimiter`, the value, the
// delimiter again; a random delimiter per record, os.EOL between the lines), so a test reads the records
// back instead of pinning bytes. GitHub keeps the last record for a repeated name, and so does this reader.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** The step's output file as the runner provides it: pre-created, empty, and named by GITHUB_OUTPUT. */
export function stepOutputFile(dir: string): string {
  const file = join(dir, "output");
  writeFileSync(file, "");
  process.env.GITHUB_OUTPUT = file;
  return file;
}

export function stepOutputs(file: string): Record<string, string> {
  const records: Record<string, string> = {};
  for (const m of readFileSync(file, "utf8").matchAll(
    /^(.+?)<<(\S+)\r?\n([\s\S]*?)\r?\n\2\r?\n/gm,
  )) {
    records[m[1] as string] = m[3] as string;
  }
  return records;
}
