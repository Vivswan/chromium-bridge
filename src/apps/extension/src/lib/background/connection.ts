// The one connection object the service worker holds per native-messaging connect, and the hook set a background
// module registers into port.ts with. port.ts imports the modules (never the reverse), so the shared types live here.

/** One native-messaging connect. port.ts mints it, hands it to every collaborator's onAttach, and it is the identity a
 * module compares against after an await: the Connection it was handed is live only while port.ts still holds it, so
 * `held === current` is the whole currency check and a reply or a mark meant for a replaced connection is dropped. */
export interface Connection {
  /** Position in this service-worker life's connect sequence, strictly increasing. */
  readonly generation: number;
  /** Post one frame to the host. False once this connection is no longer the live one, or when the port threw; the
   * caller reads false as "the frame did not reach the pipe". */
  post(frame: object): boolean;
}

/** onFrame returns true when it claimed the frame; the guards behind it must be disjoint
 * (tests/background/port-routing.test.ts pins that over the generated frame table). */
export interface PortCollaborator {
  onAttach(conn: Connection): void;
  onDetach(): void;
  onFrame?(frame: unknown): boolean;
}
