// Test fixture (not shipped). __runProbe proves Chrome enforces
// storage.local.setAccessLevel(TRUSTED_CONTEXTS) with a BEFORE/AFTER control:
// it injects the SAME content-script-world read of a seeded key twice, once
// before the restriction and once after. The "before" read MUST succeed (the
// control: it shows the injection runs in a content-script world that CAN
// reach storage, so the "after" failure is the access level and not a missing
// permission or an unrelated injection error). The "after" read MUST be
// blocked. The real extension relies on exactly this Chrome behavior for #32.
globalThis.__runProbe = async (tabId) => {
  const readInContentScript = async () => {
    const res = await chrome.scripting.executeScript({
      target: { tabId },
      world: "ISOLATED", // the extension's content-script world (untrusted)
      func: async () => {
        try {
          const r = await chrome.storage.local.get("secretTrustKey");
          return { ok: true, value: r.secretTrustKey ?? null };
        } catch (e) {
          return { ok: false, err: String(e) };
        }
      },
    });
    return res?.[0]?.result;
  };

  await chrome.storage.local.set({ secretTrustKey: "SENTINEL_TRUST_VALUE" });
  // Control: a content-script read BEFORE restricting must succeed.
  const before = await readInContentScript();
  await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  const swRead = (await chrome.storage.local.get("secretTrustKey")).secretTrustKey;
  // The same content-script read AFTER restricting must be blocked.
  const after = await readInContentScript();
  return { swRead, before, after };
};
