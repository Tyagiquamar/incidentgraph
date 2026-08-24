# IncidentGraph — Build Progress

> **Living document.** Statuses: DONE · PARTIAL · BLOCKED. Every claim below
> points at files, tests and the exact verification that produced it.
> Last updated: 2026-08-24 (hardening session).

## Snapshot

| Area | Status | Evidence |
|---|---|---|
| Run leasing v2 (owner+generation+TTL heartbeat) | DONE | migrations/003, internal/runs/lease.go, agent lease tests |
| Fenced writes + stale-driver abort | DONE | SetPhaseFenced/FinishRunFenced/PauseForApproval/CreateToolCallFenced; TestExpiredLeaseReclaimed… |
| Approval pause/resume semantics | DONE | PauseForApproval (completed_at NULL), DecideApprovalTx; api/openclaw wired |
| Crash recovery after approval | DONE | TestApproved/RejectedApprovalCrashRecovery… |
| Durable idempotency per tool_call | DONE | `incidentgraph:<tool_call_id>`; fake-durable dedupe test |
| MCP authentication + hardening | DONE | internal/mcpserver (+tests); cmd fail-closed in production |
| Production config fail-closed | DONE | Config.Validate + tests; enforced in cmd/api, cmd/worker, cmd/mcp-server |
| OpenClaw token mandatory + role gates | DONE | Config.Validate; gateway_test (viewer read-only) |
| Read-only SQL defense in depth | DONE | dedicated pool + BEGIN READ ONLY + timeouts/limits; internal/tools/readonly_test.go (UPDATE rejected by DB with policy bypassed) |
| Hermes session persistence/resume/cancel | DONE (code+tests) / **live interop: NOT verified** | external_session_id columns; runner_test w/ fake server |
| Backend-aware control plane; native-v2 removed | DONE | api.Server.ForBackend registry; accepted backends = native-v1 \| hermes |
| Embedder error semantics; no silent hash fallback | DONE | Embedder(ctx)→(vec,err); identity check at query time; IG_EMBEDDING_FALLBACK opt-in only |
| Provider token usage honesty | DONE | usage_source=provider\|estimated; CostKnown flag; llm usage_test |
| Compose stack verified end-to-end | DONE | compose up: postgres healthy, api/mcp healthz 200, worker up; MCP auth smoke 401/401/200; tools/list=8; tools/call executed; write tool denied |
| Eval corpora expansion + re-baseline | DONE | 31/34 cases seeded via scripts/gencorpus+gencases; success 26%→**67.6%**, unsafe=0, halluc=0 |
| SSE dashboard + server resume/heartbeat | DONE | Last-Event-ID + heartbeats server-side; useRunEvents manual reconnect w/ since; typecheck/tests/build green |
| README (recruiter-facing) | DONE | root README.md |
| GitHub Actions on pushed HEAD | see CI section | run id recorded after push |
| Real-model smoke | PARTIAL | `cmd/evals -mode smoke` implemented; no credentials available ⇒ no numbers recorded |

## Verification log (this session)

1. gofmt clean (all Go files), go vet clean, go build clean.
2. `go test -race ./internal/...` — ALL 14 packages PASS with live Postgres
   (agent, api, config, contextx, durablemcp, evals, hermes, llm, mcpserver,
   openclaw, policy, retrieval, security, tools).
3. Seed + security suite: PASSED (26/26, 0 leaks).
4. Eval baseline regenerated: 34 cases, success 67.6%, rc 0.66, ev 0.56,
   tool acc 96.2%, unsafe 0, hallucinated 0 (docs/eval-report.md).
5. Dashboard: tsc ✓ vitest 5/5 ✓ next build ✓ (incl. new LiveEvents SSE client).
6. Docker: `docker compose build` ✓; `docker compose up -d` → postgres healthy,
   api `/healthz` 200, mcp `/healthz` 200; MCP auth smoke: no-token 401,
   wrong-token 401, valid 200; tools/list = 8 allowlisted; search_docs
   tools/call returned ingested content; restart_service denied by allowlist.
   Fixed during verification: migration advisory lock (concurrent bootstrap
   race) and Dockerfile ENTRYPOINT swallowing compose commands.

## Design notes (why)

- **Single ownership path:** runners claim their own leases inside
  Start/Resume; workers/API only decide *when* to attempt a resume. Two racing
  resumes resolve atomically; the loser gets ErrNotClaimable.
- **Fencing:** generation is the fencing token. VerifyLease runs every drive
  iteration BEFORE any mutation; critical writes have fenced variants. A stale
  driver returns silently (`staleLeaseError`) — it must not finish/fail the run;
  the current owner stays authoritative. Operator Cancel intentionally uses the
  unfenced guarded FinishRun (human authority > lease).
- **Pause ≠ terminal:** needs_approval keeps completed_at NULL and clears the
  lease; resume happens exclusively through DecideApprovalTx → scheduler claim.
- **Embeddings never degrade silently:** real-provider failure is an error;
  hash fallback exists but is explicit (`IG_EMBEDDING_FALLBACK=hash`) and
  surfaces as degraded. Document identity (provider/model/dim) is stamped on
  documents and verified before vector queries.

## Known limitations

1. Hermes/OpenClaw/DurableMCP: adapters tested against contract fakes only;
   live interop unproven (compose requires operator-supplied images by design).
2. `insufficient-evidence-abstain` still false-positive under cross-service
   filler; 2 signature-less cases (gc-pause, clock-skew) fail honestly.
3. LLM-judge inert under mock provider (by design); real-model smoke requires
   credentials not available here.
4. Budget checks occur between phases; one long LLM call can overshoot within
   a phase.
5. GitHub Actions result pending for this HEAD (updated after push).

## Deviations from spec

1. Go instead of Python/FastAPI (owner decision).
2. FAISS comparison documented as out-of-process benchmark protocol.
3. `native-v2` removed as an advertised backend until a genuinely versioned
   implementation exists (honesty requirement).
4. External integrations require operator images via docker/compose.integrations.yml
   (we refuse to ship placeholder third-party services).

## Next tasks

1. Live DurableMCP/Hermes/OpenClaw interop against real implementations.
2. Close remaining eval gaps (signature coverage for gc-pause/clock-skew,
   abstention contamination fix).
3. Real-model + real-embedding smoke run once credentials exist; record in
   docs/eval-report.md separately from mock baseline.
