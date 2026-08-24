"use client";

import { useRunEvents } from "./useRunEvents";

const badgeColor: Record<string, string> = {
  completed: "#1a7f37",
  failed: "#cf222e",
  tool_call: "#8250df",
  security_event: "#cf222e",
  approval_required: "#9a6700",
  evidence_added: "#1f6feb",
  phase_entered: "#0969da",
};

export default function LiveEvents({
  runId,
  apiUrl,
}: {
  runId: string;
  apiUrl: string;
}) {
  const { events, live } = useRunEvents({ runId, apiUrl });

  return (
    <section className="section">
      <h2>
        Live events{" "}
        <span
          className="badge"
          style={{ background: live ? "#1a7f37" : "#57606a" }}
        >
          {live ? "streaming" : "reconnecting"}
        </span>
      </h2>
      {events.length === 0 && (
        <p className="muted">Waiting for events… (persisted log replays via SSE)</p>
      )}
      <ul className="mono">
        {events.slice(-100).map((e, i) => (
          <li key={`${e.seq}-${i}`}>
            <span style={{ color: badgeColor[e.event_type] ?? "#8b949e" }}>
              #{e.seq} {e.event_type}
            </span>{" "}
            {summarize(e.payload)}
          </li>
        ))}
      </ul>
    </section>
  );
}

function summarize(p: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const k of ["phase", "step", "tool", "status", "category", "evidence_id", "termination_reason"]) {
    if (p[k] !== undefined) parts.push(`${k}=${String(p[k])}`);
  }
  return parts.join(" ");
}
