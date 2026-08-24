-- Run leasing: allows concurrent api/worker processes to claim runs without
-- double-driving them. A lease is taken when a process starts driving a run
-- and released when it finishes; expired leases mean a crashed process left
-- the run behind, making it claimable again.
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_agent_runs_claim
    ON agent_runs (started_at)
    WHERE status = 'running';
