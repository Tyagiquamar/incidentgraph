import Link from "next/link";
import { apiGet, type AgentRun, type Incident } from "../../../lib/api";
import { formatMs, pct, shortID } from "../../../lib/format";

export const dynamic = "force-dynamic";

export default async function IncidentDetail({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let incident: Incident | null = null;
  let runs: AgentRun[] = [];
  let error: string | null = null;
  try {
    const data = await apiGet<{ incident: Incident; runs: AgentRun[] }>(
      `/incidents/${id}`
    );
    incident = data.incident;
    runs = data.runs ?? [];
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      {error && <div className="error">API unreachable: {error}</div>}
      {incident && (
        <>
          <h1>{incident.title}</h1>
          <p className="muted">
            {incident.service} · {incident.severity} · opened{" "}
            {new Date(incident.created_at).toLocaleString()}
          </p>
          <p>{incident.description}</p>

          <section className="section">
            <h2>Investigation runs</h2>
            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Backend</th>
                  <th>Status</th>
                  <th>Phase</th>
                  <th>Tokens</th>
                  <th>Cost</th>
                  <th>Latency</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{shortID(r.id)}</td>
                    <td>{r.agent_backend}</td>
                    <td>{r.status}</td>
                    <td>{r.current_phase}</td>
                    <td>{r.total_tokens}</td>
                    <td>{formatMs(r.latency_ms)}</td>
                    <td className="mono">
                      {r.total_cost_cents > 0
                        ? `${r.total_cost_cents.toFixed(3)}¢`
                        : "—"}
                    </td>
                    <td>
                      <Link href={`/runs/${r.id}`}>trace →</Link>{" "}
                      <Link href={`/runs/${r.id}/evidence`}>evidence →</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {runs.length === 0 && (
              <p className="muted">No runs yet for this incident.</p>
            )}
          </section>
        </>
      )}
    </>
  );
}
