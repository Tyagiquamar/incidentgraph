import Link from "next/link";
import {
  apiGet,
  type AgentRun,
  type AgentStep,
  type ToolCall,
} from "../../../lib/api";
import { formatMs, shortID, statusColor } from "../../../lib/format";

export const dynamic = "force-dynamic";

export default async function RunTrace({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let run: AgentRun | null = null;
  let steps: AgentStep[] = [];
  let calls: ToolCall[] = [];
  let error: string | null = null;
  try {
    run = await apiGet<AgentRun>(`/runs/${id}`);
    steps = await apiGet<AgentStep[]>(`/runs/${id}/steps`);
    calls = await apiGet<ToolCall[]>(`/runs/${id}/tool-calls`);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      {error && <div className="error">API unreachable: {error}</div>}
      {run && (
        <>
          <h1>
            Run{" "}
            <span className="mono" style={{ fontSize: "inherit" }}>
              {shortID(run.id)}
            </span>
          </h1>
          <p>
            <span
              className="badge"
              style={{ background: statusColor(run.status) }}
            >
              {run.status}
            </span>{" "}
            <span className="muted">
              backend={run.agent_backend} · phase={run.current_phase} · tokens=
              {run.total_tokens}
              {run.termination_reason && ` · reason=${run.termination_reason}`}
            </span>
          </p>

          <section className="section">
            <h2>Phase timeline (persisted state machine)</h2>
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Step</th>
                  <th>State</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {steps.map((s) => (
                  <tr key={s.id}>
                    <td>{s.step_number}</td>
                    <td className="mono">{s.step_type}</td>
                    <td>{s.state}</td>
                    <td>{formatMs(s.latency_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="section">
            <h2>Tool calls</h2>
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Risk</th>
                  <th>Policy</th>
                  <th>Status</th>
                  <th>Reference / Durable execution</th>
                </tr>
              </thead>
              <tbody>
                {calls.map((c) => (
                  <tr key={c.id}>
                    <td className="mono">{c.tool_name}</td>
                    <td>{c.risk_level}</td>
                    <td>{c.policy_decision}</td>
                    <td>{c.status}</td>
                    <td className="mono">
                      {c.result_reference || c.durable_execution_id || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {calls.length === 0 && (
              <p className="muted">No tool calls recorded.</p>
            )}
          </section>

          <p className="section">
            <Link href={`/runs/${run.id}/evidence`}>
              Evidence graph for this run →
            </Link>{" "}
            · live events: <code>/runs/{shortID(run.id)}/events</code> (SSE)
          </p>
        </>
      )}
    </>
  );
}
