import {
  apiGet,
  type EvidenceEdge,
  type EvidenceNode,
  type Hypothesis,
} from "../../../../lib/api";
import { pct, shortID } from "../../../../lib/format";

export const dynamic = "force-dynamic";

export default async function EvidenceGraphPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  let hyps: Hypothesis[] = [];
  let nodes: EvidenceNode[] = [];
  let edges: EvidenceEdge[] = [];
  let error: string | null = null;
  try {
    hyps = await apiGet<Hypothesis[]>(`/runs/${id}/hypotheses`);
    nodes = await apiGet<EvidenceNode[]>(`/runs/${id}/evidence`);
    edges = await apiGet<{ hypotheses: unknown; nodes: EvidenceNode[]; edges: EvidenceEdge[] }>(
      `/runs/${id}/graph`
    ).then((g) => (Array.isArray(g) ? [] : g.edges ?? []));
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const nodeByID = new Map(nodes.map((n) => [n.id, n]));

  return (
    <>
      <h1>Evidence graph</h1>
      <p className="mono muted">run {shortID(id)}</p>
      {error && <div className="error">API unreachable: {error}</div>}

      <section className="section">
        <h2>Hypotheses</h2>
        <table>
          <thead>
            <tr>
              <th>Rank</th>
              <th>Statement</th>
              <th>Status</th>
              <th>Confidence</th>
              <th>Category</th>
            </tr>
          </thead>
          <tbody>
            {hyps.map((h) => (
              <tr key={h.id}>
                <td>{h.rank}</td>
                <td>{h.statement}</td>
                <td>{h.status}</td>
                <td>{pct(h.confidence)}</td>
                <td className="mono">{h.root_cause_category || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {hyps.length === 0 && <p className="muted">No hypotheses.</p>}
      </section>

      <section className="section">
        <h2>Evidence → hypothesis links</h2>
        <ul>
          {edges.map((e) => {
            const n = nodeByID.get(e.source_node_id);
            return (
              <li key={e.id}>
                <span
                  className="badge"
                  style={{
                    background:
                      e.relationship === "SUPPORTS" ? "#1a7f37" : "#cf222e",
                  }}
                >
                  {e.relationship}
                </span>{" "}
                <span className="mono">
                  [{n ? `E-${n.id.replaceAll("-", "").slice(0, 8)}` : "?"}]
                </span>{" "}
                ({n?.type}) → hypothesis{" "}
                <span className="mono">{shortID(e.target_hypothesis_id)}</span>{" "}
                <span className="muted">{e.rationale}</span>
              </li>
            );
          })}
        </ul>
        {edges.length === 0 && <p className="muted">No linked evidence.</p>}
      </section>

      <section className="section">
        <h2>All evidence nodes ({nodes.length})</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Type</th>
              <th>Source</th>
              <th>Trust</th>
              <th>Excerpt</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((n) => (
              <tr key={n.id}>
                <td className="mono">E-{n.id.replaceAll("-", "").slice(0, 8)}</td>
                <td>{n.type}</td>
                <td className="mono">{n.source_reference || n.source}</td>
                <td>{n.trust_level}</td>
                <td className="muted">{n.content.slice(0, 110)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
