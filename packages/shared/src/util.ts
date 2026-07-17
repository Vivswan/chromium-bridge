// Tiny helpers shared across the packages.

/**
 * Exhaustiveness backstop: a `switch` default lands here only if a union arm
 * was left unhandled, which the `never` parameter turns into a compile error
 * at the call site. The throw covers the runtime-corrupt case.
 */
export function unreachable(value: never): never {
  throw new Error(`unreachable: ${JSON.stringify(value)}`);
}
