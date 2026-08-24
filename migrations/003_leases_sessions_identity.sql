-- Lease ownership v2: renewable leases with owner identity and generation
-- fencing, plus explicit external-engine session persistence and honest
-- model-usage provenance / embedding identity.
ALTER TABLE agent_runs
    ADD COLUMN IF NOT EXISTS lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS external_session_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS external_backend TEXT NOT NULL DEFAULT '';

ALTER TABLE model_usage
    ADD COLUMN IF NOT EXISTS usage_source TEXT NOT NULL DEFAULT 'estimated';

-- Existing rows were ingested with the deterministic hash embedder.
ALTER TABLE documents
    ADD COLUMN IF NOT EXISTS embedding_provider TEXT NOT NULL DEFAULT 'hash-v1',
    ADD COLUMN IF NOT EXISTS embedding_model TEXT NOT NULL DEFAULT 'hash-v1',
    ADD COLUMN IF NOT EXISTS embedding_dim INT NOT NULL DEFAULT 1536;
