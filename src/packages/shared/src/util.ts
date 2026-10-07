/** The throw covers what the `never` parameter cannot: a corrupt value that reached a default arm at runtime. */
export function unreachable(value: never): never {
  throw new Error(`unreachable: ${JSON.stringify(value)}`);
}
