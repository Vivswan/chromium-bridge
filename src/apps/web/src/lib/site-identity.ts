// Single source of the site's identity (origin + base path), read from the
// environment at build time so the deploy hook (.github/actions/site-build, fed
// by the fleet's site leg) can retarget the site without a source edit:
//   - default                      -> project page at https://vivswan.github.io/chromium-bridge/
//   - CUSTOM_DOMAIN set on the repo -> ASTRO_SITE=https://<domain>, ASTRO_BASE=/
// Consumed only by astro.config.mjs; pages keep reading import.meta.env.BASE_URL.

/** Absolute origin the site is served from. Any trailing slash is stripped so
 *  joins with SITE_BASE never double up. */
export const SITE_ORIGIN = (process.env.ASTRO_SITE ?? "https://vivswan.github.io").replace(
  /\/+$/,
  "",
);

/** Base path, normalized to exactly one leading and one trailing slash (the
 *  domain root becomes "/"). mdLinksPlugin and every page join it as
 *  `base + relative`, so the slashes must be exact. */
const RAW_BASE = process.env.ASTRO_BASE ?? "/chromium-bridge/";
const CORE_BASE = RAW_BASE.replace(/^\/+|\/+$/g, "");
export const SITE_BASE = CORE_BASE === "" ? "/" : `/${CORE_BASE}/`;
