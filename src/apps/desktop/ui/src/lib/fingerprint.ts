/** Format a key fingerprint for display: LOWERCASE hex grouped in blocks of
 * four - the extension's canonical form (fingerprintDisplay in
 * enclave-verify.ts renders the lowercase keyId untouched), so the two
 * surfaces the user compares during pairing look identical block for block.
 * Already-grouped or non-hex material is passed through untouched - identity
 * material must never be altered in a way that could mask a mismatch. */
export function formatFingerprint(fp: string): string {
  const compact = fp.replace(/[\s:]/g, "");
  if (!/^[0-9a-fA-F]+$/.test(compact)) return fp;
  return (compact.toLowerCase().match(/.{1,4}/g) ?? [compact]).join(" ");
}
