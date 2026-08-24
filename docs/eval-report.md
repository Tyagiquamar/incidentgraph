# Evaluation & Security Report

> All numbers below are produced by actual runs of `go run ./cmd/evals` and
> `go test ./...` against the live Postgres+pgvector instance. Nothing here is
> hand-written or estimated; re-run the commands to reproduce.

## Security red-team suite

Command: `IG_DATABASE_URL=... go run ./cmd/evals -mode security`

- Fixtures: **26** adversarial payloads (datasets/injections/fixtures.json)
- Detector coverage: **26 / 26 detected** (100%)
- Policy blocks verified: 8 malicious SQL / privileged-tool requests denied
- Privilege leaks: **0**
- prompt_injection_success_rate: **0.0**

Hardening added after earlier failures (each covered by tests):

- `read_file` sensitive-path deny-list in the policy layer
  (internal/policy/readfile_guard_test.go)
- Detector patterns for destructive SQL keywords, dangerous SQL functions
  (pg_read_file/dblink/…), fake approval authority claims, malformed JSON tool
  output (internal/security/security.go + tests)
- Red-team suite evaluates attacker-chosen tool arguments (`malicious_args`),
  not just bare tool names (internal/evals/security.go)

## Eval baseline (deterministic mock investigator)

Command: `go run ./cmd/evals -mode eval -backend native-v1`
(mock provider; deterministic — safe as CI baseline)

| Metric | Value |
|---|---|
| Cases | 34 |
| Task success rate | **67.6%** (23/34) |
| Mean root-cause score | 0.66 |
| Mean evidence score | 0.56 |
| Tool accuracy | **96.2%** |
| Unsafe actions | **0** |
| Hallucinated citations | **0** |
| Injection resistance | 1.0 |
| p50 / p95 latency | ~1.1 s / ~3.0 s |
| Mean cost per case | 0.00013 ¢ (mock pricing) |

Corpus coverage: 31 of 34 cases seed their own scenario evidence
(datasets/incidents, regenerated via scripts/gencorpus). The remaining three
are deliberate pressure cases:

- `insufficient-evidence-abstain` — must abstain (currently fails: cross-service
  filler still produces a false positive; known issue).
- `gc-pause-latency`, `clock-skew-tokens` — no failure-signature coverage in the
  deterministic investigator yet; they measure honest "I don't know" behavior.

Every failing case keeps full provenance (`run_id`, incident id, final status,
report category) inside its score details for future tuning.

### Real-model smoke

`go run ./cmd/evals -mode smoke [-cases slug1,slug2,…]` runs a 5-case subset with a
real provider (requires IG_LLM_PROVIDER=openai + IG_LLM_API_KEY). Results are
reported separately from the mock baseline and are never merged with it.
No credentials were available in this environment, so no real-model numbers are
recorded here.

## Cost / usage honesty

- Token counts come from provider responses when available (`usage_source=provider`);
  otherwise they are labeled `estimated`.
- Built-in prices are ESTIMATES documented in internal/llm; unknown models set
  `cost_known=false` instead of presenting $0 as real cost.
