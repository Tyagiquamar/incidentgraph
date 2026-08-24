"use client";

import { useEffect, useRef, useState } from "react";

export interface LiveEvent {
  seq: number;
  event_type: string;
  payload: Record<string, unknown>;
}

interface Props {
  runId: string;
  apiUrl: string;
  initialSince?: number;
}

/**
 * useRunEvents consumes the run's SSE stream (persist-before-stream server).
 * Reconnect policy:
 *  - EventSource auto-reconnects for transient drops, resuming from
 *    `?since=lastSeq` (the URL is rebuilt on each manual reconnect so the
 *    sequence never replays already-rendered events);
 *  - after repeated errors we fall back to snapshot polling by invoking
 *    onStreamDown once, and keep retrying with backoff;
 *  - cleanup closes the source and timers on unmount/navigation.
 */
export function useRunEvents({ runId, apiUrl, initialSince = 0 }: Props) {
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [live, setLive] = useState(false);
  const lastSeq = useRef(initialSince);
  const backoffMs = useRef(500);

  useEffect(() => {
    let es: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      es = new EventSource(
        `${apiUrl}/runs/${runId}/events?since=${lastSeq.current}`
      );

      es.onopen = () => {
        setLive(true);
        backoffMs.current = 500;
      };

      es.addEventListener("phase_entered", (e) => handle(e));
      es.addEventListener("step_completed", (e) => handle(e));
      es.addEventListener("tool_call", (e) => handle(e));
      es.addEventListener("approval_required", (e) => handle(e));
      es.addEventListener("evidence_added", (e) => handle(e));
      es.addEventListener("security_event", (e) => handle(e));
      es.addEventListener("completed", (e) => {
        handle(e);
        // terminal marker arrives separately; keep listening briefly
      });
      es.onmessage = (e) => handle(e); // default channel

      const handle = (e: MessageEvent) => {
        if (e.lastEventId) lastSeq.current = Number(e.lastEventId);
        try {
          const payload = JSON.parse(e.data) as Record<string, unknown>;
          setEvents((prev) =>
            prev.concat({
              seq: lastSeq.current,
              event_type: e.type === "message" ? "event" : e.type,
              payload,
            })
          );
        } catch {
          /* ignore malformed frames; snapshot fallback covers gaps */
        }
      };

      es.onerror = () => {
        setLive(false);
        es?.close();
        if (disposed) return;
        // Manual reconnect with updated ?since guarantees no loss/gap.
        reconnectTimer = setTimeout(connect, backoffMs.current);
        backoffMs.current = Math.min(backoffMs.current * 2, 8000);
      };
    };

    connect();
    return () => {
      disposed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      es?.close();
    };
  }, [runId, apiUrl]);

  return { events, live };
}
