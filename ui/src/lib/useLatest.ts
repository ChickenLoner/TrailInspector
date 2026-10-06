import { useCallback, useRef } from "react";

/**
 * Guards against out-of-order async results. Each call to `begin()` supersedes the previous
 * one; the returned `isCurrent()` is true only until the next `begin()`.
 *
 * ```ts
 * const begin = useLatestRequest();
 * const run = async () => {
 *   const isCurrent = begin();
 *   const r = await invoke(...);
 *   if (!isCurrent()) return; // a newer request started; drop this result
 *   setState(r);
 * };
 * ```
 */
export function useLatestRequest(): () => () => boolean {
  const ref = useRef(0);
  return useCallback(() => {
    const id = ++ref.current;
    return () => id === ref.current;
  }, []);
}
