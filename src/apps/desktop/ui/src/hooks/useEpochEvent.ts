import { useEffect, useRef } from "react";
import { type EpochEventName, onEpochEvent } from "@/lib/epoch-events";

/** Run `handler` whenever the named epoch notice arrives (D-P4-1). The
 * handler ref is kept fresh so callers can pass closures over state without
 * resubscribing; the subscription lives for the component's lifetime. */
export function useEpochEvent(event: EpochEventName, handler: () => void): void {
  const handlerRef = useRef(handler);
  handlerRef.current = handler;
  useEffect(() => onEpochEvent(event, () => handlerRef.current()), [event]);
}
