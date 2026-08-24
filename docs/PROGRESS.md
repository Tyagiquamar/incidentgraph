# IncidentGraph — Build Progress

> **Living document.** Updated continuously as work completes.
> Legend: ✅ done · 🔨 in progress · ⬜ not started · 🟶 partial (honest notes)

**Stack decision:** Backend is **Go 1.26** (stdlib `net/http`, pgx/v5) per owner decision
(original draft said Python/FastAPI; superseded). DB: PostgreSQL 17 + pgvector.
Frontend: Next.js 15 / React 19 / TypeScript.

---

## Current status snapshot

- **Last updated:** 2026-08-24 (continuation session)
- **Verification state:** `gofmt` clean · `go vet` clean · `go build ./...` clean ·
  `go test -race ./...` all green (with live Postgres) · security suite PASSED
  (26/26, 0 leaks) · eval suite baseline recorded · dashboard typecheck+tests+build green

## Milestones

| # | Milestone | Status |
|---|-----------|--------|
| M0 | Repo skeleton, SPEC.md, PROGRESS.md | ✅ |
| M1 | Go module: config, db pool, migration runner, SQL schema (19 tables) | ✅ |
| M2 | Policy engine + trust levels + injection detector + redaction | ✅ |
| M3 | Tool system (registry, risk levels, deterministic tools) | ✅ (incl. WRITE+durable `restart_service`) |
| M4 | DurableMCP integration client + durable execution path | ✅ (integration-tested) |
| M5 | Retrieval (chunker, lexical, pgvector, hybrid) + benchmark | ✅ benchmark recorded (docs/retrieval-benchmark.md) |
| M6 | Evidence graph store | ✅ |
| M7 | Memory layers (working / episodic / semantic) | ✅ |
| M8 | LLM providers + model router + structured-output retry | ✅ (+ RunID-scoped usage tracking fixed) |
| M9 | Context engine | ✅ (+ service-aware source diversity) |
| M10 | Agent state machine + NativeAgentRunner + loop protection + approvals | ✅ integration-tested |
| M11 | Evals platform + graders + regression gate + security red-team suite | ✅ suites run & recorded |
| M12 | HTTP API + SSE + auth roles | ✅ (+ real principal attribution) |
| M13 | Ingestion pipeline + synthetic datasets | ✅ 8 scenario corpora, 34 eval cases, 26 injection fixtures |
| M14 | Hermes adapter + OpenClaw adapter + incidentgraph-mcp server | 🟶 adapters implemented; Hermes/OpenClaw tested against stubs only (external services are hypothetical) |
| M15 | Next.js dashboard (trace, evidence graph, evals, inspectors) | ✅ builds; 9 routes |
| M16 | Docker compose + CI workflows | ✅ files added; CI untested on GitHub runners |
| M17 | Full test pass (unit + integration), fixes green | ✅ local with Postgres |
| M18 | Actual benchmark + eval runs recorded in docs | ✅ docs/eval-report.md |
| M19 | Final verification + honest final report | 🟶 this document; see open items |

## Completed work detail (this continuation session)

### Agent core hardening (M10)
- **Fixed: approval pause didn't actually pause.** `pausedError` was swallowed inside
  `phaseInvestigate`, so the drive loop continued and completed runs while an approval was
  pending. Pause now propagates and stops the loop (internal/agent/phases.go).
- **Fixed: approved tool calls never executed on resume.** `Resume` looked up
  `PendingApproval` (status='pending'), but decisions are persisted *before* resume → always
  empty. Added `runs.Store.LatestApproval`; resume now executes/denies based on persisted
  decision + tool-call terminal-state guard (internal/runs/tools.go, internal/agent/native.go).
- **Fixed: cancel was cosmetic.** In-flight drive loop never observed cancellation and could
  overwrite status back to `complete`. Added in-process cancel registry + per-phase refresh of
  persisted run state; `FinishRun` is now guarded (`status <> ALL(terminal)`) so stale drivers
  cannot overwrite terminal outcomes (internal/agent/native.go, internal/runs/store.go).
- **Fixed: token/cost budget checks were dead code** (cached run struct never refreshed).
  Drive loop now reloads run totals from Postgres each phase; MAX_TOKENS/MAX_COST terminate
  with recorded reasons.
- **Fixed: `MaxSameToolRepeats` unreachable** — check moved before the once-per-round skip;
  counts persisted history across resumes.
- **Fixed: investigate/hypothesis/verify phases persisted no steps** — every phase now writes
  a structured AgentStep (spec §7 "every phase persisted").
- Resume precedence bug (`err == nil && tc.Status == "approved" || ...`) fixed.

### Durable execution made reachable (M4)
- New WRITE-risk tool `restart_service` (`Durable: true`) — the full chain is now exercisable
  end-to-end: policy requires human approval → run pauses at NEEDS_APPROVAL → approve/reject →
  execution through DurableMCP with persisted `durable_execution_id` + event timeline.
- Degraded mode proven: when DurableMCP is unavailable the approved call fails explicitly as
  `degraded` — never silently executed locally (internal/agent/phases.go executeApproved).

### Model usage tracking fix (M8)
- **Fixed: usage rows were written against a NULL run id** and run totals never accumulated:
  `GenRequest` had no RunID field. Router now propagates RunID into every UsageRecord;
  runner passes it on every LLM call (internal/llm/llm.go, internal/agent/*).

### Run leasing (M12/M17)
- Migration `002_run_leases.sql` adds `agent_runs.lease_expires_at`.
- `ClaimNext` (FOR UPDATE SKIP LOCKED + lease) used by worker loop and API restart-recovery;
  `ClaimRun` leases before async driving in `startRun`. Multiple api/worker processes can no
  longer double-drive a run.

### Auth attribution (M12)
- **Fixed:** `authRoleName` returned hardcoded `"operator"`. auth middleware now attaches a
  Principal (role + name) to request context; `approvals.decided_by` records the real caller
  ("operator"/"admin"/"local-admin"/"openclaw:<uid>") (internal/auth/auth.go, internal/api).

### Security suite red→green (M11) — details in docs/eval-report.md
- Detector gaps closed: destructive SQL keywords, dangerous SQL functions
  (pg_read_file/dblink/lo_import/…), fake-approval authority claims ("skip approval",
  unanchored "ADMIN NOTE:"), malformed JSON tool output.
- **Policy gap closed:** `read_file` sensitive-path deny-list (/etc/passwd, .ssh/id_rsa,
  .aws/credentials, *.pem, secrets…) enforced deterministically — an injected document can no
  longer steer read_file into credential stores. Covered by internal/policy/readfile_guard_test.go.
- Red-team suite upgraded to evaluate attacker-chosen tool arguments (`malicious_args`),
  not just bare tool names.

### Eval platform (M11)
- Per-case corpus seeding wired: cases with `corpus_dir` ingest their own scenario evidence
  before running (ingest.IngestScenarioDocs + Runner.DatasetRoot); seeded paths recorded in
  score details for provenance.
- `ForbiddenActions` now enforced by graders (tool-name matches + `no_write_remediation`
  semantic check over recommended actions).
- Regression gate fail-closed when a baseline is requested but unresolvable.
- Grader unit tests added (root-cause enum/partial credit, evidence citation coverage,
  trajectory tool accuracy, hallucinated citations, unsafe counting, aggregation,
  regression-gate rules): internal/evals/graders_test.go.

### Mock investigator honesty improvements (drives eval numbers)
- Always plans query_metrics (metric-visible incidents were missing it entirely).
- Corroboration rule: a non-insufficient hypothesis needs ≥2 supporting evidence items;
  otherwise explicit abstention (spec §33–38 scenario 5).
- metricSeriesFor maps queue/lag/consumer symptoms to queue_lag series.
- Context build prefers same-service documents (source diversity, spec §16); other-service
  docs are filler only.

### Integration test harness (M17)
- `internal/testdb`: creates isolated migration-fresh databases per test; skips cleanly when
  IG_TEST_DATABASE_URL unset so plain `go test ./...` stays green without infrastructure.
- New suites: agent state machine (happy path w/ full trace assertions, approval pause→approve→
  durable execution, rejection, degraded mode, cancel-mid-flight finality, token-budget
  termination, TOOL_LOOP guard), API (hermes-backend honest 503, role enforcement incl.
  admin-only evals, approval principal attribution, OpenClaw webhook investigate/approve),
  policy read_file guard, security detector regressions, eval grader units.
- Fake DurableMCP server (httptest) implements MCP initialize/tools/call + REST reads for the
  durable-path tests.

### Adapters (M14)
- **HermesAgentRunner** implemented against OUR contract (POST /api/runs/start,
  GET /api/runs/{session}, POST …/stop): maps session events into AgentSteps + run_events,
  persists everything in Postgres, fails explicitly as BACKEND_UNAVAILABLE when Hermes is
  down — never silently substitutes the native engine (internal/hermes/runner.go).
- Backend selection is now honest: `{"backend":"hermes"}` returns 503 with explanation when
  unconfigured/unreachable instead of silently running native-v1 (internal/api/handlers.go).
- **OpenClaw ingress wired**: POST /openclaw/webhook (verify-token protected) handles
  `/incident investigate|approve|reject|cancel|evidence` with registered principals and role
  checks; approvals attribute decided_by=openclaw:<user> (internal/api/openclaw.go).
- incidentgraph-mcp server unchanged (already complete): JSON-RPC over HTTP, 8-tool read-only
  allowlist, policy evaluation + defense-in-depth SQL re-check, denied calls → security_events.

### Dashboard (M15)
Next.js 15 App Router, TypeScript strict. Routes: `/` (landing hero + capabilities),
`/incidents`, `/incidents/[id]` (runs w/ tokens/cost/latency), `/runs/[id]` (phase timeline +
tool calls incl. durable execution refs), `/runs/[id]/evidence` (hypotheses, SUPPORTS/
CONTRADICTS links, node table w/ trust levels), `/evals` (totals + regression gate column),
`/retrieval` (mode selector over lexical/vector/hybrid/rerank), `/memory` (semantic + episodic
inspectors), `/security` (event log). Verified: `tsc --noEmit` ✓, vitest 5/5 ✓,
`next build` production ✓ (all 9 routes).

### Docker + CI (M16)
- `docker-compose.yml`: postgres(pgvector) + api + worker + mcp-server default; optional
  profiles `durablemcp`, `hermes`, `openclaw`. Mock LLM provider by default.
- `docker/Dockerfile`: multi-stage Go build, non-root user.
- `.github/workflows/ci.yml`: gofmt-enforced, vet, race tests with pgvector service container,
  fresh-database seed validation, security-suite gate, eval-suite gate; frontend job
  (npm ci → typecheck → test → build); docker image build. No `|| true`, no continue-on-error,
  no skipped tests.

## Verification results (this session)

| Check | Result |
|---|---|
| gofmt -l . | clean |
| go vet ./... | clean |
| go build ./... | clean |
| go test -race ./internal/... (IG_TEST_DATABASE_URL set) | ALL PASS (agent, api, contextx, durablemcp, evals, llm, policy, retrieval, security) |
| go test ./... without DB env | PASS (integration tests skip honestly) |
| cmd/seed on fresh schema | OK (8 scenarios ingested) |
| cmd/evals -mode security | PASSED — 26/26 detected, 0 leaks, rate 0.0 |
| cmd/evals -mode eval -backend native-v1 | exit 0 — baseline recorded (34 cases, 0 unsafe, 0 hallucinated) |
| dashboard typecheck / vitest / next build | PASS / 5 passed / 9 routes built |

## Known limitations (explicit)

1. **Hermes/OpenClaw/DurableMCP are external services that do not exist in this repo.**
   Our adapters define the wire contracts, are covered by httptest-based tests, and degrade
   explicitly — but there has been no live interop against real third-party implementations.
2. **25 of 34 eval cases have no scenario corpus.** They exercise abstention/failure behavior,
   not retrieval quality. Expanding datasets/incidents + mock failure signatures would raise
   measured success rate meaningfully.
3. **LLM-as-judge is inert under the mock provider by design** (refuses to fabricate semantic
   judgment); blended scoring activates only with a real provider.
4. Budget checks happen between phases; a single long LLM call can overshoot within a phase.
5. CI workflow file exists but has not run on GitHub Actions yet (no remote configured).
6. Docker image build not yet executed locally (network-dependent golang image pull);
   compose file mirrors CI expectations.

## Deviations from spec (explicit)

1. **Backend language:** Python/FastAPI → **Go** (owner instruction at kickoff).
2. FAISS comparison: documented out-of-process benchmark protocol; primary vector DB is
   pgvector (spec allows optional FAISS).
3. Hermes/OpenClaw: adapters behind compose profiles; never required for default dev.
4. Mock model provider is first-class (spec §47–55 requires deterministic mocked responses
   for CI). All metrics produced with it are labeled as such.

## Next tasks (in order)

1. Expand synthetic corpora to cover ≥20 more eval scenarios + matching mock failure
   signatures; re-baseline eval suite.
2. Live-interop smoke for DurableMCP/Hermes/OpenClaw against real implementations.
3. Wire SSE consumption into dashboard run page (endpoint already streams; page polls snapshot today).
4. Push repo to remote and validate ci.yml on GitHub Actions.
