// Dark-mode: toggle .dark on <html> to follow the OS. The extension UI has no
// theme setting (it tracks the system), so this is a thin matchMedia bridge.
// A synchronous read of prefers-color-scheme before first paint avoids a flash.

export function applyTheme(prefersDark: boolean): void {
  document.documentElement.classList.toggle("dark", prefersDark);
}

export function initTheme(): void {
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  applyTheme(mq.matches);
  mq.addEventListener("change", (e) => applyTheme(e.matches));
}
