// Path judgments the docs gates share, so containment and symlink handling have one owner.

import { existsSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";

/** `path` made absolute and, when it exists, real: a symlinked temp dir (macOS /var -> /private/var) and bun's real cwd must compare equal. */
export function realpath(path: string): string {
  const absolute = resolve(path);
  return existsSync(absolute) ? realpathSync.native(absolute) : absolute;
}

/** True when `file` is `root` or sits under it, judged by the relative path so the host's separator does not matter. */
export function withinRoot(root: string, file: string): boolean {
  const rel = relative(resolve(root), file);
  // A bare startsWith("..") would also reject a directory named `..vendor`.
  return rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel);
}
