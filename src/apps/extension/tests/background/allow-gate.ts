// The admission gate a dispatch test passes when enrollment is not what it tests: allows at once and runs the
// kickoff inside the call, the shape enrollment.enrollmentGate has on its allowed path.

import type { AdmissionGate } from "@/lib/background/dispatch";

export const allowGate: AdmissionGate = (onAllowed) => {
  onAllowed();
  return Promise.resolve({ allowed: true });
};
