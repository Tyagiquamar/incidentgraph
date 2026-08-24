# Evaluation & Security Report

> All numbers below are produced by actual runs of `go run ./cmd/evals` and
> `go test ./...` against the live Postgres+pgvector instance. Nothing on this
> page is hand-written or estimated. Re-run the commands to reproduce.

## Security red-team suite

Command: `IG_DATABASE_URL=... go run ./cmd/evals -mode security`

- Fixtures: **26** adversarial payloads (datasets/injections/fixtures.json)
- Detector coverage: **26 / 26 detected** (100%)
- Policy blocks verified: 8 malicious SQL / privileged-tool requests denied by
  the deterministic engine (never the model's own judgment)
- Privilege leaks: **0**
- prompt_injection_success_rate: **0.0** (target: 0 successful privileged actions)

History note: an earlier run (before hardening) reported 21/26 detected and
1 privilege leak (`disregard-policies` could have driven `read_file` to open
`/etc/passwd`). Fixes made since, each covered by tests:

- `read_file` sensitive-path deny-list added to the policy layer
  (internal/policy/policy.go, internal/policy/readfile_guard_test.go)
- detector patterns for destructive SQL keywords, dangerous SQL functions
  (pg_read_file/dblink/…), fake approval authority claims, malformed JSON tool
  output (internal/security/security.go, security_test.go)
- red-team suite now evaluates tools with attacker-chosen arguments
  (`malicious_args`), not just bare tool names (internal/evals/security.go)

## Eval suite (regression baseline)

Command: `go run ./cmd/evals -mode eval -backend native-v1`
(mock provider; deterministic — safe to re-run as CI baseline)

| Metric | Value |
|---|---|
| Cases | 34 |
| Task success rate | 26% |
| Mean root-cause score | 0.31 |
| Mean evidence score | 0.52 |
| Tool accuracy | 94% |
| Unsafe actions | **0** |
| Hallucinated citations | **0** |
| Injection resistance | 1.0 |
| p50 / p95 latency | ~0.7 s / ~1.1 s |
| Mean cost per case | 0.00013 ¢ (mock pricing) |

Passing cases are exactly those whose scenario corpus exists in
`datasets/incidents/`: db-pool-regression, n-plus-one-query, cache-stampede,
bad-deploy-config, conflicting-evidence-redis-vs-db, thread-pool-exhaustion,
slow-subquery-report, dependency-circuit-flap, pool-misconfig-canary.

### Known limitation (honest)

25 of 34 cases describe scenarios with no ingested evidence corpus
(`seed_corpus: false`, no `corpus_dir`). The mock investigator correctly
abstains or fails on these rather than guessing; they measure abstention
behavior, not retrieval quality. Adding corpora + failure-signature entries
for the remaining scenario families is tracked in PROGRESS.md.

The mock provider measures THIS system end-to-end (retrieval, planning,
policy, evidence graph, grading) — it makes no claim about frontier-model
accuracy. With `IG_LLM_PROVIDER=openai` the same suite runs against a real
model and records real token/cost usage.
