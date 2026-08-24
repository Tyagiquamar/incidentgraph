import Link from "next/link";
import { apiGet, type Incident } from "../lib/api";

export const dynamic = "force-dynamic";

const capabilities = [
  {
    title: "Persisted agent runs",
    body: "Every phase of every investigation is a row in Postgres. Runs survive restarts, pause for approvals and resume exactly where they stopped.",
  },
  {
    title: "Evidence graph, not prose",
    body: "Hypotheses are linked to typed evidence nodes with SUPPORTS / CONTRADICTS edges. The final report must cite graph nodes.",
  },
  {
    title: "Deterministic authorization",
    body: "A policy engine outside the LLM decides what tools may run: read-only auto-approved, writes require humans, privileged is forbidden.",
  },
  {
    title: "Durable tool execution",
    body: "Side-effecting calls execute through DurableMCP with idempotency keys and inspectable event timelines — never silently local.",
  },
  {
    title: "Hybrid retrieval over pgvector",
    body: "Lexical (Postgres FTS) + vector (pgvector HNSW) search with documented scoring, reranking and an inspector for every query.",
  },
  {
    title: "Trajectory evals + red teaming",
    body: "Deterministic graders score tool choice, evidence grounding and unsafe actions; a 26-fixture injection suite gates every change.",
  },
];

export default async function Home() {
  let recent: Incident[] = [];
  let error: string | null = null;
  try {
    recent = await apiGet<Incident[]>("/incidents?limit=5");
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <>
      <section className="hero">
        <h1>Investigate incidents with agents you can actually audit.</h1>
        <p>
          IncidentGraph runs autonomous incident investigations on your own
          runbooks, logs, deployments and metrics — with persisted state,
          deterministic guardrails, durable tool execution and evaluation built
          in. This demo uses synthetic data only.
        </p>
      </section>

      {error && <div className="error">API unreachable: {error}</div>}
      {!error && (
        <section>
          <h2>Recent incidents</h2>
          <table>
            <tbody>
              {recent.map((inc) => (
                <tr key={inc.id}>
                  <td>
                    <Link href={`/incidents/${inc.id}`}>{inc.title}</Link>
                  </td>
                  <td className="muted">{inc.service}</td>
                  <td className="muted">{inc.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="grid section">
        {capabilities.map((c) => (
          <div key={c.title} className="card">
            <h3>{c.title}</h3>
            <p>{c.body}</p>
          </div>
        ))}
      </section>
    </>
  );
}
