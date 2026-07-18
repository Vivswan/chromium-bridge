/** Format a key fingerprint for display: uppercase, grouped in blocks of
 * four, so it can be compared block by block against the extension popup.
 * Already-grouped or non-hex material is passed through untouched - identity
 * material must never be altered in a way that could mask a mismatch. */
export function formatFingerprint(fp: string): string {
  const compact = fp.replace(/[\s:]/g, "");
  if (!/^[0-9a-fA-F]+$/.test(compact)) return fp;
  return (compact.toUpperCase().match(/.{1,4}/g) ?? [compact]).join(" ");
}
