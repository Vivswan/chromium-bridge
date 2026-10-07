/** A JS-safe integer can still lie past the range Date represents (about 8.64e15 ms either side of the epoch);
 * such a timestamp shows raw, in the unit the host wrote it, rather than as "Invalid Date". */
export function localTime(value: number, unit: "ms" | "s"): string {
  const date = new Date(unit === "s" ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}
