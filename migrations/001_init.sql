-- IncidentGraph initial schema.
-- PostgreSQL 15+ / pgvector 0.5+ required.
-- Normalized columns for queryable fields; JSONB only for structured payloads.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS schema_migrations (
    name       text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------- incidents
CREATE TABLE incidents (
    id          uuid PRIMARY KEY,
    title       text NOT NULL,
    description text NOT NULL DEFAULT '',
    service     text NOT NULL,
    severity    text NOT NULL DEFAULT 'sev3',
    status      text NOT NULL DEFAULT 'open',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_incidents_service ON incidents(service);
CREATE INDEX idx_incidents_created ON incidents(created_at DESC);

-- ---------------------------------------------------------------- agent_runs
CREATE TABLE agent_runs (
    id                 uuid PRIMARY KEY,
    incident_id        uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    agent_backend      text NOT NULL,            -- native-v1 | native-v2 | hermes
    model              text NOT NULL DEFAULT '',
    status             text NOT NULL,            -- running|complete|failed|cancelled|needs_approval
    current_phase      text NOT NULL,            -- received|context_build|plan|investigate|hypothesis|verify|synthesize
    termination_reason text NOT NULL DEFAULT '', -- SUCCESS|MAX_STEPS|MAX_COST|TOOL_LOOP|CANCELLED|FAILED|...
    total_tokens       bigint NOT NULL DEFAULT 0,
    total_cost_cents   numeric(12,6) NOT NULL DEFAULT 0,
    latency_ms         bigint NOT NULL DEFAULT 0,
    error              text NOT NULL DEFAULT '',
    started_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz
);
CREATE INDEX idx_runs_incident ON agent_runs(incident_id);
CREATE INDEX idx_runs_status   ON agent_runs(status);

-- ---------------------------------------------------------------- agent_steps
CREATE TABLE agent_steps (
    id                 uuid PRIMARY KEY,
    run_id             uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    step_number        int  NOT NULL,
    step_type          text NOT NULL,           -- context_build|plan|tool_batch|hypothesis|verify|synthesize|approval_wait
    state              text NOT NULL DEFAULT 'succeeded', -- succeeded|failed|waiting_approval
    structured_input   jsonb NOT NULL DEFAULT '{}'::jsonb,
    structured_output  jsonb NOT NULL DEFAULT '{}'::jsonb,
    context_manifest   jsonb NOT NULL DEFAULT '[]'::jsonb,
    latency_ms         bigint NOT NULL DEFAULT 0,
    error              text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, step_number)
);
CREATE INDEX idx_steps_run ON agent_steps(run_id, step_number);

-- ---------------------------------------------------------------- tool_calls
CREATE TABLE tool_calls (
    id                   uuid PRIMARY KEY,
    run_id               uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    step_id              uuid REFERENCES agent_steps(id) ON DELETE SET NULL,
    tool_name            text NOT NULL,
    arguments            jsonb NOT NULL DEFAULT '{}'::jsonb,
    redacted_arguments   jsonb NOT NULL DEFAULT '{}'::jsonb,
    risk_level           text NOT NULL,          -- read_only|write|privileged
    policy_decision      text NOT NULL DEFAULT '', -- allowed|denied|needs_approval
    status               text NOT NULL,          -- pending|approved|executing|succeeded|failed|denied|timeout|degraded
    attempt              int NOT NULL DEFAULT 1,
    result_reference     text NOT NULL DEFAULT '',
    result_size_bytes    int NOT NULL DEFAULT 0,
    error                text NOT NULL DEFAULT '',
    durable_execution_id text NOT NULL DEFAULT '',
    durable_namespace    text NOT NULL DEFAULT '',
    idempotency_key      text NOT NULL DEFAULT '',
    requested_at         timestamptz NOT NULL DEFAULT now(),
    started_at           timestamptz,
    completed_at         timestamptz
);
CREATE INDEX idx_tool_calls_run ON tool_calls(run_id);
CREATE INDEX idx_tool_calls_tool ON tool_calls(tool_name);

CREATE TABLE tool_call_events (
    id           bigserial PRIMARY KEY,
    tool_call_id uuid NOT NULL REFERENCES tool_calls(id) ON DELETE CASCADE,
    event_type   text NOT NULL,                 -- requested|policy_checked|submitted|lease_granted|completed|failed|retry_scheduled|stale_rejected
    payload      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_tce_call ON tool_call_events(tool_call_id, id);

-- ---------------------------------------------------------------- documents / chunks
CREATE TABLE documents (
    id           uuid PRIMARY KEY,
    source_type  text NOT NULL,                 -- markdown|log|runbook|postmortem|git_diff|source_code|metrics|json
    service      text NOT NULL DEFAULT '',
    path         text NOT NULL DEFAULT '',
    title        text NOT NULL DEFAULT '',
    trust_level  text NOT NULL DEFAULT 'internal_document', -- system_trusted|user_provided|internal_document|external_untrusted|tool_output
    content_hash text NOT NULL,
    raw_content  text NOT NULL,
    metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_documents_hash ON documents(content_hash);
CREATE INDEX idx_documents_service ON documents(service, source_type);

CREATE TABLE document_chunks (
    id           uuid PRIMARY KEY,
    document_id  uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    chunk_index  int  NOT NULL,
    content      text NOT NULL,
    content_hash text NOT NULL,
    token_count  int  NOT NULL DEFAULT 0,
    embedding    vector(1536),
    tsv          tsvector GENERATED ALWAYS AS (to_tsvector('english', content)) STORED,
    metadata     jsonb NOT NULL DEFAULT '{}'::jsonb, -- source_type,service,path,timestamp,trust_level,chunk_index
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (document_id, chunk_index)
);
CREATE INDEX idx_chunks_doc ON document_chunks(document_id);
CREATE INDEX idx_chunks_tsv ON document_chunks USING gin(tsv);
CREATE INDEX idx_chunks_embedding ON document_chunks USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------------- memories
CREATE TABLE memories (
    id          uuid PRIMARY KEY,
    kind        text NOT NULL,                  -- working|episodic|semantic
    run_id      uuid REFERENCES agent_runs(id) ON DELETE CASCADE,
    incident_id uuid REFERENCES incidents(id) ON DELETE SET NULL,
    key         text NOT NULL,
    content     text NOT NULL,
    metadata    jsonb NOT NULL DEFAULT '{}'::jsonb,
    embedding   vector(1536),
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_memories_kind ON memories(kind);
CREATE INDEX idx_memories_run  ON memories(run_id);
CREATE INDEX idx_memories_embedding ON memories USING hnsw (embedding vector_cosine_ops);

-- ---------------------------------------------------------------- hypotheses
CREATE TABLE hypotheses (
    id           uuid PRIMARY KEY,
    run_id       uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    statement    text NOT NULL,
    confidence   real NOT NULL DEFAULT 0,
    status       text NOT NULL DEFAULT 'proposed', -- proposed|verified|rejected|selected
    rank         int  NOT NULL DEFAULT 0,
    root_cause_category text NOT NULL DEFAULT '', -- machine-matchable enum e.g. db_pool_regression
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_hypotheses_run ON hypotheses(run_id);

-- ---------------------------------------------------------------- evidence graph
CREATE TABLE evidence_nodes (
    id               uuid PRIMARY KEY,
    run_id           uuid REFERENCES agent_runs(id) ON DELETE CASCADE,
    chunk_id         uuid REFERENCES document_chunks(id) ON DELETE SET NULL,
    type             text NOT NULL,             -- log|doc|commit|metric|deployment|schema|tool_output|other
    source           text NOT NULL,
    source_reference text NOT NULL DEFAULT '',
    content          text NOT NULL,
    trust_level      text NOT NULL DEFAULT 'tool_output',
    dedupe_hash      text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, dedupe_hash)
);
CREATE INDEX idx_evidence_run ON evidence_nodes(run_id);

CREATE TABLE evidence_edges (
    id                  uuid PRIMARY KEY,
    source_node_id      uuid NOT NULL REFERENCES evidence_nodes(id) ON DELETE CASCADE,
    target_hypothesis_id uuid NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    relationship        text NOT NULL,           -- SUPPORTS|CONTRADICTS|DERIVED_FROM|DUPLICATES|CORRELATES_WITH
    rationale           text NOT NULL DEFAULT '',
    confidence          real NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_node_id, target_hypothesis_id, relationship)
);
CREATE INDEX idx_eedges_hyp ON evidence_edges(target_hypothesis_id);

-- ---------------------------------------------------------------- approvals
CREATE TABLE approvals (
    id           uuid PRIMARY KEY,
    run_id       uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    tool_call_id uuid REFERENCES tool_calls(id) ON DELETE SET NULL,
    tool         text NOT NULL,
    arguments    jsonb NOT NULL DEFAULT '{}'::jsonb,
    risk         text NOT NULL,
    reason       text NOT NULL DEFAULT '',
    status       text NOT NULL DEFAULT 'pending', -- pending|approved|rejected
    requested_by text NOT NULL DEFAULT '',
    decided_by   text NOT NULL DEFAULT '',
    decided_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_approvals_run ON approvals(run_id);
CREATE INDEX idx_approvals_status ON approvals(status);

-- ---------------------------------------------------------------- evals
CREATE TABLE eval_cases (
    id                     uuid PRIMARY KEY,
    slug                   text NOT NULL UNIQUE,
    title                  text NOT NULL,
    dataset_version        text NOT NULL DEFAULT 'v1',
    incident_payload       jsonb NOT NULL,
    expected_root_cause    text NOT NULL,
    acceptable_root_causes text[] NOT NULL DEFAULT '{}',
    required_evidence      text[] NOT NULL DEFAULT '{}',
    expected_tools         text[] NOT NULL DEFAULT '{}',
    forbidden_tools        text[] NOT NULL DEFAULT '{}',
    forbidden_actions      text[] NOT NULL DEFAULT '{}',
    distractor_doc_paths   text[] NOT NULL DEFAULT '{}'
);

CREATE TABLE eval_runs (
    id                  uuid PRIMARY KEY,
    agent_backend       text NOT NULL,
    model               text NOT NULL DEFAULT '',
    dataset_version     text NOT NULL DEFAULT 'v1',
    baseline_eval_run_id uuid REFERENCES eval_runs(id) ON DELETE SET NULL,
    status              text NOT NULL DEFAULT 'running', -- running|complete|failed
    totals              jsonb NOT NULL DEFAULT '{}'::jsonb,
    regression_vs_baseline jsonb NOT NULL DEFAULT '{}'::jsonb,
    started_at          timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz
);

CREATE TABLE eval_scores (
    id                       uuid PRIMARY KEY,
    eval_run_id              uuid NOT NULL REFERENCES eval_runs(id) ON DELETE CASCADE,
    case_slug                text NOT NULL,
    task_success             boolean NOT NULL DEFAULT false,
    root_cause_score         real NOT NULL DEFAULT 0,
    evidence_score           real NOT NULL DEFAULT 0,
    tool_accuracy            real NOT NULL DEFAULT 0,
    unsafe_action_count      int NOT NULL DEFAULT 0,
    hallucinated_claim_count int NOT NULL DEFAULT 0,
    unnecessary_tool_calls   int NOT NULL DEFAULT 0,
    latency_ms               bigint NOT NULL DEFAULT 0,
    total_tokens             bigint NOT NULL DEFAULT 0,
    cost_cents               numeric(12,6) NOT NULL DEFAULT 0,
    details                  jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_eval_scores_run ON eval_scores(eval_run_id);

-- ---------------------------------------------------------------- model_usage
CREATE TABLE model_usage (
    id             bigserial PRIMARY KEY,
    run_id         uuid REFERENCES agent_runs(id) ON DELETE CASCADE,
    eval_run_id    uuid REFERENCES eval_runs(id) ON DELETE CASCADE,
    provider       text NOT NULL,
    model          text NOT NULL,
    task_type      text NOT NULL,               -- classification|query_expansion|hypothesis_synthesis|judge|embedding
    input_tokens   int NOT NULL DEFAULT 0,
    output_tokens  int NOT NULL DEFAULT 0,
    latency_ms     bigint NOT NULL DEFAULT 0,
    estimated_cost numeric(12,6) NOT NULL DEFAULT 0,
    status         text NOT NULL DEFAULT 'ok',  -- ok|error|timeout
    retry_count    int NOT NULL DEFAULT 0,
    error          text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_model_usage_run ON model_usage(run_id);

-- ---------------------------------------------------------------- security_events
CREATE TABLE security_events (
    id               bigserial PRIMARY KEY,
    run_id           uuid REFERENCES agent_runs(id) ON DELETE SET NULL,
    tool_call_id     uuid REFERENCES tool_calls(id) ON DELETE SET NULL,
    source           text NOT NULL,             -- retrieved_doc|tool_output|user_message|memory|model_output
    category         text NOT NULL,             -- prompt_injection|sql_destructive|destructive_shell|credential_exfil|fake_approval|loop_bait|malformed_tool_output|encoded_instruction|instruction_conflict|data_poisoning
    detected_content text NOT NULL DEFAULT '',
    decision         text NOT NULL,             -- blocked|flagged|allowed
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_security_run ON security_events(run_id);
CREATE INDEX idx_security_cat ON security_events(category);

-- ---------------------------------------------------------------- run_events (SSE replay log)
CREATE TABLE run_events (
    seq        bigserial PRIMARY KEY,
    run_id     uuid NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    event_type text NOT NULL,                   -- phase_entered|step_completed|tool_call|security_event|approval_required|completed|failed
    payload    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_run_events_run ON run_events(run_id, seq);
