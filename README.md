# IncidentGraph

**Auditable AI incident-investigation platform built in Go.**

Give it an incident ("checkout latency went from 180ms to 2.6s after deploy") and an
agent investigates your runbooks, logs, deployments, diffs and metrics — then returns
ranked hypotheses, an evidence graph, and a report where **every claim cites evidence
nodes** you can inspect. Not a chatbot: a production-shaped agent system where the
model proposes and deterministic infrastructure disposes.

---

## Why this is not an LLM wrapper

| Capability | How IncidentGraph does it |
|---|---|
| Persisted agent state machine | `RECEIVED → CONTEXT_BUILD → PLAN → INVESTIGATE → HYPOTHESIS → VERIFY → SYNTHESIZE → COMPLETE` (+`FAILED/CANCELLED/NEEDS_APPROVAL`). Every phase is a Postgres row; runs survive restarts (`internal/agent`). |
| Resumable execution w/ fencing | Renewable leases (`lease_owner` + `lease_generation` + TTL heartbeat at TTL/3). Stale drivers are fenced at every phase boundary and cannot mutate a reclaimed run (`internal/runs/lease.go`, migration 003). |
| Durable tool execution | Side-effecting tools execute only via DurableMCP with stable per-call idempotency keys (`incidentgraph:<tool_call_id>`) persisted *before* submission; unavailable DurableMCP ⇒ explicit `degraded`, never silent local execution. |
| Deterministic authorization | A policy engine outside the LLM classifies every call: READ_ONLY auto-approved, WRITE requires human approval, PRIVILEGED forbidden. SQL guard blocks destructive statements/functions; `read_file` has a sensitive-path deny-list. |
| Human approvals | Write calls pause the run (`needs_approval`, `completed_at` stays NULL) and persist an approval record. The decision is applied atomically (approval + tool call + run transition in one transaction); recovery is via the normal fenced scheduler. |
| Prompt-injection defense | Retrieved docs & tool outputs are DATA: regex detector (injection/exfil/destructive-SQL/encoded/malformed-JSON families) downgrades trust, records SecurityEvents, and never promotes embedded instructions to authority. 26-fixture red-team suite gates every change. |
| Hybrid retrieval | Postgres FTS (lexical) + pgvector HNSW (semantic) with documented scoring `0.45·lex_norm + 0.55·cos_sim`, optional coverage reranker, and embedding-identity tracking so corpora can't be queried across incompatible vector spaces. |
| Evidence graph | Typed nodes (log/metric/commit/deployment/doc) linked to hypotheses via SUPPORTS / CONTRADICTS edges; phantom citations are filtered before persistence and counted by graders. |
| Memory | Working (per-run plan/observations), episodic (past trajectories), semantic (pgvector over past incidents) — all untrusted context, all inspectable via API/dashboard. |
| Evals | 34-case dataset with per-case corpora, deterministic graders (root-cause enum, required-evidence presence+citation, forbidden tools/actions, unsafe-action counting, hallucinated-citation detection), trajectory tool accuracy, rubric scoring, optional LLM judge (real providers only), and a fail-closed regression gate. |
| Model routing | Task-based router (classification/hypothesis/judge tiers) with primary→fallback failover, structured-output JSON retry with bounded corrections, and usage records that distinguish **provider-measured vs estimated** tokens and flag unknown-model cost as unknown. |
| Observability | Structured JSON logs, trace IDs, persisted run event log replayed over SSE (Last-Event-ID + heartbeats), tool-call timelines incl. durable execution drill-down, model-usage roll-ups. |

## Architecture

```text
 User / Dashboard        OpenClaw (optional chat ingress)
        │                          │
        ▼                          ▼
┌──────────────────────────────────────────────┐
│                IncidentGraph API             │
│   incidents · runs · SSE · approvals · evals │
└───────────────┬──────────────────────────────┘
                │ RunnerRegistry (backend-aware)
      ┌─────────┴─────────┐
      ▼                   ▼
 NativeRunner        HermesRunner (optional)
 (Go, in-repo)       remote loop, our tools via MCP
      │                   │
      └────────┬──────────┘
               ▼
   Fenced run lease + state machine (Postgres = source of truth)
               │
   ┌───────────┼─────────────┬──────────────┐
   ▼           ▼             ▼              ▼
Retrieval   Policy Engine  Evidence     Memory (working/
(FTS+pgvector) (outside LLM) Graph      episodic/semantic)
   └───────────┴──────┬──────┘
                      ▼
                 Tools (8 read-only + write-via-approval)
                      │ side-effecting only
                      ▼
                DurableMCP substrate (idempotent, event-timelined)
```

## Key guarantees

1. Two drivers can never own one run: claims atomically bump a generation; renewal/release/fenced writes require exact `(owner, generation)` match.
2. An approved action survives crashes: decision transaction flips the run back to `running`; any driver resumes from the persisted decision and the durable idempotency key guarantees exactly-once execution.
3. The LLM never authorizes anything. It proposes; policy + humans decide.
4. Injection payloads stay data. Flagged content remains available as evidence with downgraded trust and a SecurityEvent trail.
5. Metrics are measured, not invented: graders compute scores from persisted trajectories; token counts are labeled provider-vs-estimated; the red-team suite verifies actual enforcement, not self-report.

## Retrieval benchmark

Generated by `go run ./cmd/bench-retrieval` against the synthetic corpus — see
[docs/retrieval-benchmark.md](docs/retrieval-benchmark.md) for the current table
(Recall@5/@10, MRR, p50/p95 for lexical / vector / hybrid / hybrid+rerank).
Embedder identity is recorded alongside results (deterministic `hash-v1` unless a
real provider is configured).

## Eval & security results

Generated from actual suite runs — see [docs/eval-report.md](docs/eval-report.md):

- Security red-team: **26/26 fixtures detected, 0 privilege leaks, prompt-injection success rate 0**.
- Eval baseline (mock provider): 34 cases, ~68% task success, **0 unsafe actions,
  0 hallucinated citations**, tool accuracy ≈96%. Numbers regenerate via
  `go run ./cmd/evals -mode eval -backend native-v1`.

## Demo scenarios

Synthetic corpora cover: DB pool regression, N+1/slow reporting query, cache stampede,
queue backlog + poison message, disk/WAL saturation, log flood, downstream timeout +
circuit flapping, third-party rate limit, deadlock + migration lock, DNS failure,
expired secret + certificate expiry, feature-flag regression/drift, retry storm +
duplicate charges, connection leak, thread-pool starvation, memory-leak OOM,
schema drift, blue-green reset storm, autoscaler flap, bad deploy config, plus a
prompt-injection runbook and deliberate insufficient-evidence cases.

## Local run

```bash
docker compose up -d          # postgres(pgvector) + api(:8090) + worker + mcp(:8091)
go run ./cmd/seed             # ingest synthetic corpora + incidents
# investigate:
curl -X POST localhost:8090/incidents -H 'Content-Type: application/json' \
  -d '{"title":"Checkout latency 180ms->2.6s","service":"checkout","severity":"sev2",
       "description":"Checkout latency increased after deployment; db pool exhausted"}'
open http://localhost:3000    # dashboard (apps/dashboard, npm run dev)
```

Tests:

```bash
IG_TEST_DATABASE_URL='postgres://incidentgraph:incidentgraph@localhost:5433/incidentgraph?sslmode=disable' \
  go test -race ./...
cd apps/dashboard && npm ci && npm run typecheck && npm test && npm run build
```

MCP (authenticated):

```bash
curl -H 'Authorization: Bearer dev-mcp-token' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' localhost:8091/mcp
```

## Architecture docs

- [docs/SPEC.md](docs/SPEC.md) — approved product/engineering specification.
- [docs/PROGRESS.md](docs/PROGRESS.md) — honest build status with verification evidence.
- [docs/eval-report.md](docs/eval-report.md) · [docs/retrieval-benchmark.md](docs/retrieval-benchmark.md)

## Known limitations

- Hermes/OpenClaw/DurableMCP adapters define our wire contracts and are covered by
  httptest-based tests; live interop against real third-party implementations has not
  been performed (compose requires operator-supplied images on purpose).
- LLM-as-judge stays inert under the mock provider (we refuse fabricated semantic
  judgment); blended scoring activates only with a real provider.
- 11 of 34 eval cases still fail honestly under the deterministic investigator
  (missing failure-signature coverage or deliberately unsolvable); per-case provenance
  (run_id) is stored for future tuning.

## What this is NOT

- Not autonomous remediation: writes need a human click; nothing auto-executes.
- Not a generic chatbot / RAG-demo: no free-form chat surface exists.
- No employer or proprietary incident data: every corpus file is synthetic and
  generated by scripts/gencorpus.
