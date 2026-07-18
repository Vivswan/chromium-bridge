import { useCallback, useEffect, useRef, useState } from "react";
import { errorText } from "@/lib/tauri";

/** Load data from a Tauri command with reload support. Errors become the
 * Rust error string; a reload keeps the previous data visible until the new
 * result lands. */
export function useAsync<T>(fn: () => Promise<T>): {
  data: T | undefined;
  error: string | undefined;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  const reload = useCallback(() => {
    const mySeq = ++seq.current;
    setLoading(true);
    fnRef
      .current()
      .then((value) => {
        if (seq.current !== mySeq) return;
        setData(value);
        setError(undefined);
      })
      .catch((err: unknown) => {
        if (seq.current !== mySeq) return;
        setError(errorText(err));
      })
      .finally(() => {
        if (seq.current === mySeq) setLoading(false);
      });
  }, []);

  useEffect(() => {
    reload();
    // Invalidate any in-flight request on unmount so a late resolution
    // cannot set state on an unmounted hook.
    return () => {
      seq.current += 1;
    };
  }, [reload]);

  return { data, error, loading, reload };
}
