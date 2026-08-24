import { apiGet } from "../../lib/api";
import { shortID } from "../../lib/format";

export const dynamic = "force-dynamic";

interface WorkingItem {
  key: string;
  content: string;
}

interface MemorySearchResponse {
  episodic_recent: { key: string; incident_id: string; content: string }[];
  semantic_matches: {
    kind: string;
    key: string;
    content: string;
    score: number;
  }[];
}

export default async function MemoryPage({
  searchParams,
}: {
  searchParams: Promise<{ q?: string }>;
}) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  let data: MemorySearchResponse | null = null;
  let error: string | null = null;
  if (q) {
    try {
      data = await apiGet<MemorySearchResponse>(
        `/memory/search?q=${encodeURIComponent(q)}`
      );
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  return (
    <>
      <h1>Memory inspector</h1>
      <p className="muted">
        Working memory holds the current run&apos;s plan and observations;
        episodic memory records past trajectories; semantic memory (pgvector)
        surfaces similar past incidents. Memory is untrusted context — shown
        here for inspection, never followed as instructions.
      </p>
      <form method="get" className="section">
        <input
          type="text"
          name="q"
          defaultValue={q}
          placeholder="semantic query e.g. pool exhausted"
          size={48}
        />{" "}
        <button type="submit">Search memory</button>
      </form>

      {error && <div className="error">{error}</div>}
      {data && (
        <>
          <section className="section">
            <h2>Semantic matches</h2>
            <table>
              <tbody>
                {(data.semantic_matches ?? []).map((m) => (
                  <tr key={m.kind + m.key}>
                    <td>{m.kind}</td>
                    <td className="mono">{m.key}</td>
                    <td className="mono">{m.score.toFixed(3)}</td>
                    <td className="muted">{m.content}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {(data.semantic_matches ?? []).length === 0 && (
              <p className="muted">No matches.</p>
            )}
          </section>
          <section className="section">
            <h2>Recent episodes</h2>
            <ul>
              {(data.episodic_recent ?? []).map((ep) => (
                <li key={ep.key}>
                  <span className="mono">{shortID(ep.incident_id)}</span> —{" "}
                  {ep.content}
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </>
  );
}
