// Control Tower color constants for the contexts that cannot read CSS custom
// properties: browser.action badges and the inline-styled content-script
// toast. These hexes MIRROR the token layer in src/assets/styles.css (source
// of truth: design-explorations/control-tower/theme.css) - when a token
// changes there, change it here too.

/* Action badges float over the browser chrome, whose color we cannot know,
 * so they use the dark-scheme signal hexes (the saturated variants) in both
 * modes. */

/** --pending (dark scheme): waiting on the user (a pairing approval, a
 * new-origin decision). */
export const BADGE_PENDING_COLOR = "#f5b942";

/** --danger (dark scheme): the bridge is blocked (killed, unpaired, or
 * failed closed). */
export const BADGE_DANGER_COLOR = "#f2555a";

/** Neutral surface + ink hexes for the in-page info toast, one set per
 * color scheme (the content script picks via prefers-color-scheme). */
export interface ToastPalette {
  /** card background (--surface-3) */
  surface: string;
  /** primary ink (--text-1) */
  text: string;
  /** secondary ink (--text-2) */
  textSecondary: string;
  /** card + button border (--edge-strong) */
  edgeStrong: string;
  /** button fill one step below the card (light --surface-0 / dark --surface-4) */
  control: string;
}

export const TOAST_LIGHT: ToastPalette = {
  surface: "#ffffff",
  text: "#16202c",
  textSecondary: "#3f5165",
  edgeStrong: "rgba(22, 32, 44, 0.27)",
  control: "#f6f8fa",
};

export const TOAST_DARK: ToastPalette = {
  surface: "#161b24",
  text: "#e8edf4",
  textSecondary: "#9aa7b8",
  edgeStrong: "#2e3846",
  control: "#1b212c",
};
