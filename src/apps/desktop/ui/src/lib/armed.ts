import type { EnclaveStatusReport } from "@/lib/tauri";

/** The ONE armed/attested predicate, shared by every view (Overview,
 * Security). Green claims about the host hang off this and nothing else:
 * the enclave key must exist, the presence policy must be enrolled, the
 * enclave read itself must have succeeded (useAsync keeps the previous
 * data after a failed reload - stale data proves nothing), and the latest
 * status refresh must have succeeded (fail-closed display).
 *
 * Deliberately keyed on SETTLED reads: while a reload is in flight the last
 * settled answer keeps rendering (no unknown-flash on every window focus);
 * the moment a read settles as a failure, the claim drops. */
export function isArmed(
  enclave: { data: EnclaveStatusReport | undefined; error: string | undefined },
  statusFresh: boolean,
): boolean {
  return (
    enclave.error === undefined &&
    enclave.data?.key === "present" &&
    enclave.data.policy?.enrolled === true &&
    statusFresh
  );
}
