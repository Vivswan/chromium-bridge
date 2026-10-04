// A Connection minted outside port.ts: a suite drives one collaborator at a time, so a post callback stands in for
// the native port. Returns the Connection so a test can hold the stale one across a re-attach.

import type { Connection, PortCollaborator } from "@/lib/background/connection";

let generations = 0;

export function attach(
  collaborator: PortCollaborator,
  post: (frame: object) => boolean = () => true,
): Connection {
  const conn: Connection = { generation: ++generations, post };
  collaborator.onAttach(conn);
  return conn;
}
