import { apiGet } from "../../lib/api";
import { shortID } from "../../lib/format";

export const dynamic = "force-dynamic";

interface SecurityEvent {
  id: number;
  run_id: string | null;
  source: string;
  category: string;
  detected_content: string;
  decision: string;
  created_at: string;
}

export default async function SecurityPage() {
  let events: SecurityEvent[] = [];
  let error: string | null = null;
  try {
    events = await apiGet<SecurityEvent[]>("/security/events?limit=100");
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      <h1>Security events</h1>
      <p className="muted">
        Injection attempts detected in retrieved documents and tool outputs,
        plus every denied tool request. Content is data, never instructions —
        flagged material stays available as evidence with downgraded trust.
      </p>
      {error && <div className="error">API unreachable: {error}</div>}
      {!error && (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Run</th>
              <th>Source</th>
              <th>Category</th>
              <th>Decision</th>
              <th>Detected content</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id}>
                <td>{ev.id}</td>
                <td className="mono">
                  {ev.run_id ? shortID(ev.run_id) : "—"}
                </td>
                <td>{ev.source}</td>
                <td className="mono">{ev.category}</td>
                <td>{ev.decision}</td>
                <td className="muted mono">
                  {ev.detected_content.slice(0, 100)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!error && events.length === 0 && (
        <p className="muted">No security events recorded yet.</p>
      )}
    </>
  );
}
