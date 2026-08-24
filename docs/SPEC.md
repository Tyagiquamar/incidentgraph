# IncidentGraph / AgentOps — Product & Engineering Specification

> Status: **Approved specification**. This document is the source of truth for scope.
> Progress is tracked in [PROGRESS.md](./PROGRESS.md).

Build a production-shaped AI agent reliability and incident investigation platform.

This is NOT a generic chatbot.
This is NOT "chat with your PDF".
This is NOT a LangChain demo.
This is NOT an LLM wrapper.

The goal is to demonstrate production AI-agent engineering for roles involving:

- agent orchestration
- tool use
- MCP
- RAG / retrieval
- vector databases
- memory
- evals
- LLM-as-judge
- prompt-injection defense
- guardrails
- human approval
- model routing
- observability
- failure recovery
- structured outputs
- agent traces
- backend systems

The product's concrete default use case is:

**AUTONOMOUS INCIDENT INVESTIGATION.**

A user provides an incident such as:

> "Checkout latency increased from 180ms to 2.6s after deployment.
> Find the likely root cause and show evidence."

The agent can investigate:

- source code
- GitHub commits / diffs
- application logs
- deployment history
- runbooks
- architecture documentation
- database schema
- read-only SQL
- metrics fixtures
- previous incidents

It must produce:

- ranked hypotheses
- evidence supporting each hypothesis
- contradicting evidence
- root cause
- recommended actions
- confidence
- full trace
- evaluation results

---

## 0. CORE PRODUCT PRINCIPLE

The most important architecture decision:

DO NOT make Hermes, OpenClaw, LangChain, LangGraph or any other framework
the core business logic.

IncidentGraph owns:

- run lifecycle
- state persistence
- tool policy
- retrieval
- memory
- evidence graph
- evaluation
- security
- approval
- observability

Agent engines are pluggable.

At minimum support:

1. `NativeAgentRunner` (implemented in this repo, Go)
2. `HermesAgentRunner` (optional adapter)

OpenClaw should be treated primarily as an optional messaging gateway.

Conceptually:

```text
interface AgentRunner:
    start(run)
    step(run)
    resume(run)
    cancel(run)
```

This lets us benchmark Native vs Hermes over the exact same incident dataset.

## 1. REPOSITORY STRUCTURE

Clean monorepo:

```text
incidentgraph/
  cmd/                 # Go binaries: api, worker, ingest, seed, evals, bench-retrieval, mcp-server
  internal/            # Go packages: policy, security, tools, durablemcp, retrieval,
                       #   evidence, memory, contextx, llm, agent, hermes, openclaw,
                       #   evals, observability, auth, api, model, db, config
  apps/dashboard/      # Next.js + TypeScript dashboard
  datasets/
    incidents/         # synthetic incident scenarios
    injections/        # adversarial prompt-injection fixtures
    retrieval/         # retrieval benchmark queries + relevance judgments
  migrations/          # PostgreSQL SQL migrations (embedded)
  integrations notes: hermes/openclaw/durablemcp adapters live under internal/
  docs/                # SPEC.md, PROGRESS.md, architecture, benchmarks
  docker/              # Dockerfiles
  scripts/             # dev helpers
  .github/workflows/   # CI
```

### Stack decision record

The original draft specified Python 3.12+/FastAPI. **Owner decision: the backend is
implemented in Go** (net/http stdlib router, pgx v5 for PostgreSQL). Rationale: the
companion DurableMCP service is Go; a single-language backend keeps the durable tool
path, worker pool and MCP server idiomatic and dependency-light.

Primary stack:

- Backend: **Go 1.22+** (`net/http`, `encoding/json`, pgx/v5)
- Database: PostgreSQL + pgvector
- Retrieval: Postgres full-text (lexical) + pgvector (semantic) hybrid; optional FAISS comparison documented as out-of-process benchmark
- Frontend: Next.js + TypeScript
- Observability: structured JSON logs, trace IDs propagated end-to-end; OpenTelemetry-compatible fields where practical
- Infrastructure: Docker, Docker Compose, GitHub Actions

Do not add dependencies merely for keywords.

## 2. DATABASE MODEL

PostgreSQL as the source of truth. Explicit schemas/tables for:

incidents, agent_runs, agent_steps, tool_calls, tool_call_events, documents,
document_chunks, memories, hypotheses, evidence_nodes, evidence_edges, approvals,
eval_cases, eval_runs, eval_scores, model_usage, security_events.

Proper IDs, timestamps, foreign keys and indexes.

Important concepts:

- Incident: id, title, description, service, severity, created_at
- AgentRun: id, incident_id, agent_backend, model, status, current_phase, started_at, completed_at, total_tokens, total_cost, latency_ms
- AgentStep: run_id, step_number, step_type, structured_input, structured_output, state
- ToolCall: run_id, tool_name, arguments, risk_level, status, started_at, completed_at, result_reference
- Hypothesis: run_id, statement, confidence, status
- EvidenceNode: type, source, source_reference, content, trust_level
- EvidenceEdge: source_node, target_hypothesis, relationship

Relationships: SUPPORTS, CONTRADICTS, DERIVED_FROM, DUPLICATES, CORRELATES_WITH

Do not store the entire system only as JSON blobs. Use normalized columns for
important queryable fields.

## 3. EVIDENCE GRAPH

Major differentiator. The agent must not simply produce prose — build an evidence graph.

Example:

- Hypothesis H1: "Database connection pool regression caused checkout latency."
  - E1: deployment diff changed pool_size 40 -> 5 — SUPPORTS H1
  - E2: DB wait time increased after deployment — SUPPORTS H1
  - E3: CPU remained stable — SUPPORTS H1 indirectly
  - E4: Redis latency remained stable — CONTRADICTS competing hypothesis H2

Store this graph. Expose API:

```
GET /runs/{id}/hypotheses
GET /runs/{id}/evidence
GET /runs/{id}/graph
```

Final answer must cite graph nodes.

## 4. INGESTION PIPELINE

Ingestion for: Markdown, plain text, JSON logs, stack traces, runbooks, incident
postmortems, Git diffs, source-code text, PDF optional.

Pipeline: raw document -> normalize -> classify -> chunk -> metadata -> embedding ->
Postgres + pgvector -> lexical index.

Every chunk includes metadata: document_id, source_type, service, path, timestamp,
trust_level, content_hash, chunk_index.

Structure-aware chunking (Markdown headings, code functions/classes, log temporal
groups, runbook sections) — not blind 500-token windows.

## 5. HYBRID RETRIEVAL

A. lexical retrieval; B. vector retrieval via pgvector; C. hybrid; D. optional reranking.

Structured RetrievalResult: chunk_id, document_id, text, lexical_score, vector_score,
combined_score, rank, metadata. Hybrid scoring must be explicit and documented.

## 6. RETRIEVAL BENCHMARK

50–100 queries with relevant document/chunk IDs. Measure Recall@5, Recall@10, MRR,
nDCG if practical, p50/p95 latency. Compare lexical only / vector only / hybrid /
hybrid + reranker. Results go in `docs/retrieval-benchmark.md`, populated ONLY from
actual runs.

Optional FAISS backend: purpose is comparison vs pgvector on the same embeddings
(index build time, query p50/p95, Recall@K, memory).

## 7. AGENT RUN STATE MACHINE

RECEIVED -> CONTEXT_BUILD -> PLAN -> INVESTIGATE -> HYPOTHESIS -> VERIFY ->
SYNTHESIZE -> COMPLETE. Terminal: COMPLETE, FAILED, CANCELLED, NEEDS_APPROVAL.

No `while true: call_llm()` without persisted structure. Every phase persisted;
runs survive restarts.

## 8. NATIVE AGENT ORCHESTRATOR

Implement NativeAgentRunner in-repo. Provider interface: generate(),
generate_structured(), stream(). Pydantic-style schemas => Go structs validated after
JSON decode, with bounded correction retries.

Schemas: InvestigationPlan{objectives[], tools_needed[], risks[], completion_criteria[]},
HypothesisCandidate{claim, supporting_evidence_ids[], contradicting_evidence_ids[],
confidence}, IncidentReport{summary, root_cause, confidence, supporting_evidence[],
contradictory_evidence[], recommended_actions[], unresolved_questions[]}.

## 9. TOOL SYSTEM

Tools: search_docs, search_logs, get_deployment, get_git_diff, read_file, search_code,
query_metrics, query_postgres_readonly.

Each tool: name, description, input schema, output schema, risk level, timeout,
permissions. Risks: READ_ONLY (auto), WRITE (human approval), PRIVILEGED (blocked).

## 10. DURABLEMCP INTEGRATION

Integrate the existing DurableMCP project as durable execution substrate via a client.
Persist invocation before execution; stable tool-call ID; idempotency key; timeout;
retries where safe; inspectable execution state. IncidentGraph stores references to
DurableMCP execution IDs; trace UI links step -> execution -> event timeline.
If DurableMCP unavailable: degraded state, never silently execute risky tools outside
the durable path.

## 11. PROMPT INJECTION DEFENSE

Retrieved content is DATA, not trusted instructions. Trust levels: SYSTEM_TRUSTED,
USER_PROVIDED, INTERNAL_DOCUMENT, EXTERNAL_UNTRUSTED, TOOL_OUTPUT.

Injection detector/policy pipeline. Content remains available as evidence; instructions
inside it never promoted to authority; dangerous tool calls denied; SecurityEvent recorded
(run_id, source, category, detected_content, decision, tool_call_id, timestamp).

## 12. SECURITY RED-TEAM DATASET

>= 25 adversarial fixtures across: direct injection, indirect injection, tool output
poisoning, instruction conflict, credential exfiltration, SQL destruction, destructive
shell, infinite tool-loop bait, fake approval, data poisoning, malformed tool output,
encoded instruction. Eval: prompt_injection_success_rate; target 0 successful privileged
actions; verify actual tool-policy behavior, not LLM self-report.

## 13. POLICY ENGINE

Deterministic enforcement OUTSIDE the LLM. SQL parser/check: SELECT allowed;
DROP/DELETE/ALTER/UPDATE blocked or approval-required. WRITE requires approval;
PRIVILEGED forbidden. The LLM must never be the sole authorization authority.

## 14. HUMAN APPROVAL

POST /approvals/{id}/approve, POST /approvals/{id}/reject. Approval record: requested_by_run,
tool, arguments, risk, reason, status, approved_by, timestamp. Run pauses at NEEDS_APPROVAL
and resumes exactly from persisted state.

## 15. MODEL ROUTING

Task-based routing: classification/expansion -> cheap model; hypothesis synthesis ->
strong model; evaluation -> judge model. Primary + fallback. Record every invocation
(provider, model, tokens, latency, cost, status, retry_count); expose usage.

## 16. CONTEXT ENGINE

Deduplication, token budgeting, trust-aware ordering, source diversity, recency weighting,
provenance. ContextItem: content, source, trust, token_count, retrieval_score,
reason_selected. Record final context manifest per step.

## 17. AGENT MEMORY

Working (current run plan/observations/hypotheses), Episodic (past incident trajectories),
Semantic (pgvector over past incidents/failure patterns). Memory retrieval inspectable;
memory is untrusted context.

## 18. EVALUATION PLATFORM

30+ cases (target 50+): input, available evidence, expected root cause, acceptable wording,
required evidence, forbidden actions, expected tools, distractors. Include: db pool regression,
N+1, cache stampede, downstream timeout, bad deploy config, connection leak, queue backlog,
disk saturation, rate limit, deadlock, DNS issue, expired secret, broken feature flag,
incorrect retry policy.

## 19. GRADERS

Deterministic (required/forbidden tools, cited evidence, no privileged exec, root-cause enum),
rubric (quality/grounding/completeness/actionability), LLM-as-judge (only semantic dims),
trajectory grader (tool selection/order/loops/retries/unsafe requests).

## 20. EVAL OUTPUT

Per run: task_success, root_cause_score, evidence_score, tool_accuracy, unsafe_action_count,
hallucinated_claim_count, unnecessary_tool_calls, latency, tokens, cost. Aggregates: success
rate, p50/p95 latency, mean cost, injection resistance, tool accuracy. No fabricated metrics.

## 21. REGRESSION GATE

`go run ./cmd/evals` supports baseline comparison; CI fails on regression. unsafe_actions > 0
=> immediate failure.

## 22–24. HERMES

Optional HermesAgentRunner mapping Hermes lifecycle events into AgentStep. Hermes +
incidentgraph-mcp server exposing allowlisted tools through policy + DurableMCP.
Benchmark mode compares native-v1/native-v2/hermes on identical dataset.

## 25–26. OPENCLAW

Optional ingress/messaging adapter (Slack/Telegram first): create runs, post status,
approve/reject/cancel commands, identity mapping viewer/operator/admin.

## 27–32. OBSERVABILITY & UI

Tool observability fields (requested/started/completed, latency, status, attempt, args,
redacted args, result size, error, durablemcp execution id). Trace UI timeline, evidence
graph UI, eval dashboard with trend/regression highlight, retrieval inspector, memory inspector.

Frontend pages: `/`, `/incidents`, `/incidents/[id]`, `/runs/[id]`, `/runs/[id]/evidence`,
`/evals`, `/retrieval`, `/memory`, `/security`.

Landing hero: "Investigate incidents with agents you can actually audit."

## 33–38. DATA & DEMO SCENARIOS

Synthetic services: checkout, payments, orders, notifications, inventory. Scenarios:
(1) connection pool regression POOL_SIZE 40->5; (2) N+1 query; (3) runbook prompt injection;
(4) conflicting evidence (Redis vs DB pool); (5) insufficient evidence => explicit abstention.

## 39–40. API SURFACE & REAL-TIME

POST /incidents; GET /incidents/{id}; POST /incidents/{id}/runs; GET /runs/{id};
GET /runs/{id}/steps|events|hypotheses|evidence|graph|model-usage; POST /runs/{id}/cancel;
POST /approvals/{id}/approve|reject; POST /documents; POST /search; GET /evals; POST /evals/run.
SSE preferred server->browser; persist events before streaming; reconnect replays missed events.

## 41–46. OBSERVABILITY, FAILURE HANDLING, LIMITS

Instrument HTTP, LLM calls, retrieval, rerank, tool exec, DurableMCP calls, phases, grading.
Propagate incident_id/run_id/step_id/tool_call_id. Structured logs only.
Failure handling tests: LLM timeout/malformed JSON, tool timeout/unavailable, DurableMCP
unavailable, PG reconnect, retriever error, judge failure, SSE reconnect. Explicit states,
no silent hangs. Structured-output retry bounded. Loop protection: max steps/tool calls/
same-tool reps/token/cost budgets; termination_reason recorded. Secret redaction tested.
Auth roles viewer/operator/admin.

## 47–55. FRONTEND, DEPLOYMENT, DEMO

Next.js pages as above; landing per copy guidance; deploy dashboard Vercel + API/workers
long-running Docker; compose profiles `--profile hermes`, `--profile openclaw`; GH Actions
CI (build, vet, test, integration, security suite, frontend typecheck/build, docker build,
migration validation) with NO `|| true` / continue-on-error / skipped tests; deterministic
mocked model responses for CI (no paid APIs in CI); manual live-model smoke target;
README leads with guarantees + synthetic-data statement; portfolio demo seeds 5–10 scenarios.

## 56. WHAT NOT TO DO

No generic chatbot; no RAG-as-product; no hiding orchestration behind frameworks; no exposed
chain-of-thought; no unpolicied shell; no model self-authorization; no fabricated metrics;
no calling mocked tools "real integrations"; no claiming autonomous remediation; no proprietary
data; no forking DurableMCP; Hermes/OpenClaw stay optional.

## 57–58. FINAL VERIFICATION & REPORT

Run backend unit/integration tests, policy/security tests, retrieval benchmark, small eval
suite, frontend tests/typecheck/build, Docker build, migration validation. Then answer the 15
verification questions explicitly and honestly.
