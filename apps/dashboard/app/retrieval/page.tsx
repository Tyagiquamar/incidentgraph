import { apiGet, type RetrievalResult } from "../../lib/api";

export const dynamic = "force-dynamic";

interface SearchResponse {
  query: string;
  mode: string;
  results: RetrievalResult[];
}

export default async function RetrievalInspector({
  searchParams,
}: {
  searchParams: Promise<{ q?: string; mode?: string; k?: string }>;
}) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  const mode = sp.mode ?? "hybrid";
  const k = sp.k ?? "8";
  let data: SearchResponse | null = null;
  let error: string | null = null;

  if (q) {
    try {
      const params = new URLSearchParams({ query: q, mode, k });
      data = await apiPostJSON<SearchResponse>(`/search?${params}`);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
  }

  return (
    <>
      <h1>Retrieval inspector</h1>
      <p className="muted">
        Hybrid scoring: combined = 0.45·lex_norm + 0.55·cos_sim over Postgres
        FTS + pgvector HNSW. Every agent context build is inspectable through
        this same endpoint.
      </p>
      <form method="get" className="section">
        <input
          type="text"
          name="q"
          defaultValue={q}
          placeholder="query e.g. pool exhausted after deployment"
          size={48}
        />{" "}
        <select name="mode" defaultValue={mode}>
          <option value="lexical">lexical</option>
          <option value="vector">vector</option>
          <option value="hybrid">hybrid</option>
          <option value="rerank">hybrid + rerank</option>
        </select>{" "}
        <input type="text" name="k" defaultValue={k} size={2} />{" "}
        <button type="submit">Search</button>
      </form>

      {error && <div className="error">{error}</div>}
      {data && (
        <>
          <p className="muted">
            {data.results.length} results for “{data.query}” ({data.mode})
          </p>
          <table>
            <thead>
              <tr>
                <th>Score</th>
                <th>Path</th>
                <th>Trust</th>
                <th>Excerpt</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((r) => {
                const meta = (r.metadata ?? {}) as Record<string, string>;
                return (
                  <tr key={r.chunk_id}>
                    <td className="mono">{r.combined_score.toFixed(3)}</td>
                    <td className="mono">{meta.path}</td>
                    <td>{meta.trust_level}</td>
                    <td className="muted">{r.text.slice(0, 120)}…</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}

async function apiPostJSON<T>(path: string): Promise<T> {
  const { API_URL } = await import("../../lib/api");
  const res = await fetch(`${API_URL}${path}`, { method: "POST", cache: "no-store" });
  if (!res.ok) throw new Error(`POST failed: ${res.status}`);
  return (await res.json()) as T;
}
