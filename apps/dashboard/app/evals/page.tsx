import { apiGet } from "../../lib/api";
import { pct } from "../../lib/format";

export const dynamic = "force-dynamic";

interface EvalTotals {
  case_count: number;
  success_rate: number;
  mean_root_cause_score: number;
  mean_evidence_score: number;
  mean_tool_accuracy: number;
  unsafe_actions: number;
  hallucinated_claims: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  mean_cost_cents: number;
  injection_resistance: number;
}

interface EvalRunRow {
  id: string;
  backend: string;
  model: string;
  dataset_version: string;
  status: string;
  totals: EvalTotals | null;
  regression: { passed?: boolean; reasons?: string[] } | null;
  started_at: string;
}

export default async function EvalsPage() {
  let runs: EvalRunRow[] = [];
  let error: string | null = null;
  try {
    const data = await apiGet<{ runs: EvalRunRow[] }>("/evals");
    runs = data.runs ?? [];
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      <h1>Evaluation runs</h1>
      <p className="muted">
        Metrics are computed by deterministic graders over recorded agent
        trajectories. unsafe_actions &gt; 0 fails the regression gate
        immediately; the LLM judge is only active with a real provider.
      </p>
      {error && <div className="error">API unreachable: {error}</div>}
      {!error && (
        <table>
          <thead>
            <tr>
              <th>Run</th>
              <th>Backend</th>
              <th>Cases</th>
              <th>Success</th>
              <th>Evidence</th>
              <th>Tool acc.</th>
              <th>Unsafe</th>
              <th>Halluc.</th>
              <th>p50 / p95</th>
              <th>Gate</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.id.slice(0, 8)}</td>
                <td>{r.backend}</td>
                <td>{r.totals?.case_count ?? "—"}</td>
                <td>{r.totals ? pct(r.totals.success_rate) : "—"}</td>
                <td>{r.totals ? pct(r.totals.mean_evidence_score) : "—"}</td>
                <td>{r.totals ? pct(r.totals.mean_tool_accuracy) : "—"}</td>
                <td>{r.totals?.unsafe_actions ?? "—"}</td>
                <td>{r.totals?.hallucinated_claims ?? "—"}</td>
                <td className="mono">
                  {r.totals
                    ? `${r.totals.p50_latency_ms}ms / ${r.totals.p95_latency_ms}ms`
                    : "—"}
                </td>
                <td>{r.regression?.passed === false ? "FAILED" : "passed"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {runs.length === 0 && !error && (
        <p className="muted">
          No eval runs yet. Start one with{" "}
          <code>go run ./cmd/evals -mode eval</code>.
        </p>
      )}
    </>
  );
}
