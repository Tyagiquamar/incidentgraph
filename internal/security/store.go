package security

import (
	"context"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists security events. Detection never silently passes: blocked
// content is still available as evidence, but its instructions are quarantined
// by trust level and the event is always recorded.
type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func (s *Store) Record(ctx context.Context, ev model.SecurityEvent) error {
	const q = `INSERT INTO security_events (run_id, tool_call_id, source, category, detected_content, decision)
	           VALUES ($1,$2,$3,$4,$5,$6)`
	_, err := s.pool.Exec(ctx, q, ev.RunID, ev.ToolCallID, ev.Source, ev.Category,
		ev.DetectedContent, ev.Decision)
	return err
}

func (s *Store) ListForRun(ctx context.Context, runID string, limit int) ([]model.SecurityEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, tool_call_id, source, category, detected_content, decision, created_at
	    FROM security_events WHERE run_id=$1 ORDER BY id DESC LIMIT $2`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityEvent
	for rows.Next() {
		var e model.SecurityEvent
		if err := rows.Scan(&e.ID, &e.RunID, &e.ToolCallID, &e.Source, &e.Category,
			&e.DetectedContent, &e.Decision, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ListRecent(ctx context.Context, limit int) ([]model.SecurityEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, tool_call_id, source, category, detected_content, decision, created_at
	    FROM security_events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SecurityEvent
	for rows.Next() {
		var e model.SecurityEvent
		if err := rows.Scan(&e.ID, &e.RunID, &e.ToolCallID, &e.Source, &e.Category,
			&e.DetectedContent, &e.Decision, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
