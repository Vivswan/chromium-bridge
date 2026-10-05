// Worker-scoped state. A service worker dies within minutes and every module-level slot starts over on its next life,
// so a cell holds only what that life owns (a live connection, an in-flight exchange, a lane's queue); anything a
// restart must keep is in browser.storage. The lint plugin (../../../lint/module-scope-let.grit) refuses a bare
// module-scope `let` under lib/, so every such slot is a cell: enumerable, and reset to the first life's value
// without restating it.

export interface Cell<T> {
  value: T;
  /** Tests only: the first life's value again (a fresh one when `initial` builds state, such as a lane). */
  reset(): void;
}

export function inLife<T>(initial: () => T): Cell<T> {
  let value = initial();
  return {
    get value() {
      return value;
    },
    set value(next: T) {
      value = next;
    },
    reset() {
      value = initial();
    },
  };
}
