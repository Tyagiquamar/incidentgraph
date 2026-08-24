package runs

import (
	"context"
	"encoding/json"

	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/model"
)

// ---------------------------------------------------------------- tool calls

func (s *Store) CreateToolCall(ctx context.Context, tc model.ToolCall) error {
	if tc.ID == "" {
		tc.ID = model.New()
	}
	if tc.Status == "" {
		tc.Status = "pending"
	}
	if tc.Attempt == 0 {
		tc.Attempt = 1
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO tool_calls
	    (id, run_id, step_id, tool_name, arguments, redacted_arguments, risk_level, policy_decision, status, attempt, idempotency_key)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		tc.ID, tc.RunID, tc.StepID, tc.ToolName, emptyJSON(tc.Arguments), emptyJSON(tc.RedactedArguments),
		tc.RiskLevel, tc.PolicyDecision, tc.Status, tc.Attempt, tc.IdempotencyKey)
	return err
}

func (s *Store) UpdateToolCallPolicy(ctx context.Context, id, decision, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tool_calls SET policy_decision=$2, status=$3 WHERE id=$1`, id, decision, status)
	return err
}

func (s *Store) StartToolCall(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tool_calls SET status='executing', started_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) CompleteToolCall(ctx context.Context, id, status, resultRef string, sizeBytes int, errMsg string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tool_calls SET status=$2, result_reference=$3, result_size_bytes=$4,
	    error=$5, completed_at=now() WHERE id=$1`, id, status, resultRef, sizeBytes, errMsg)
	return err
}

func (s *Store) SetDurableRef(ctx context.Context, id, execID, namespace string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tool_calls SET durable_execution_id=$2, durable_namespace=$3 WHERE id=$1`,
		id, execID, namespace)
	return err
}

func (s *Store) ToolCallEvent(ctx context.Context, callID, eventType string, payload any) error {
	b, _ := json.Marshal(payload)
	_, err := s.pool.Exec(ctx, `INSERT INTO tool_call_events (tool_call_id, event_type, payload) VALUES ($1,$2,$3)`,
		callID, eventType, b)
	return err
}

const toolCallCols = `id, run_id, step_id, tool_name, arguments, redacted_arguments, risk_level, policy_decision,
	status, attempt, result_reference, result_size_bytes, error, durable_execution_id, durable_namespace,
	idempotency_key, requested_at, started_at, completed_at`

func scanToolCall(row interface{ Scan(...any) error }) (model.ToolCall, error) {
	var t model.ToolCall
	err := row.Scan(&t.ID, &t.RunID, &t.StepID, &t.ToolName, &t.Arguments, &t.RedactedArguments,
		&t.RiskLevel, &t.PolicyDecision, &t.Status, &t.Attempt, &t.ResultReference,
		&t.ResultSizeBytes, &t.Error, &t.DurableExecutionID, &t.DurableNamespace,
		&t.IdempotencyKey, &t.RequestedAt, &t.StartedAt, &t.CompletedAt)
	return t, err
}

func (s *Store) GetToolCall(ctx context.Context, id string) (*model.ToolCall, error) {
	t, err := scanToolCall(s.pool.QueryRow(ctx, `SELECT `+toolCallCols+` FROM tool_calls WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Store) ToolCalls(ctx context.Context, runID string) ([]model.ToolCall, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+toolCallCols+` FROM tool_calls WHERE run_id=$1 ORDER BY requested_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ToolCall
	for rows.Next() {
		t, err := scanToolCall(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ToolCallTimeline(ctx context.Context, callID string) ([]model.ToolCallEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, tool_call_id, event_type, payload, created_at
	    FROM tool_call_events WHERE tool_call_id=$1 ORDER BY id`, callID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ToolCallEvent
	for rows.Next() {
		var e model.ToolCallEvent
		if err := rows.Scan(&e.ID, &e.ToolCallID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- approvals

func (s *Store) CreateApproval(ctx context.Context, a model.Approval) (string, error) {
	if a.ID == "" {
		a.ID = model.New()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO approvals (id, run_id, tool_call_id, tool, arguments, risk, reason, status)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		a.ID, a.RunID, a.ToolCallID, a.Tool, emptyJSON(a.Arguments), a.Risk, a.Reason, orDefault(a.Status, "pending"))
	return a.ID, err
}

func (s *Store) GetApproval(ctx context.Context, id string) (*model.Approval, error) {
	var a model.Approval
	err := s.pool.QueryRow(ctx, `SELECT id, run_id, tool_call_id, tool, arguments, risk, reason, status, requested_by, decided_by, decided_at, created_at
	    FROM approvals WHERE id=$1`, id).Scan(&a.ID, &a.RunID, &a.ToolCallID, &a.Tool, &a.Arguments,
		&a.Risk, &a.Reason, &a.Status, &a.RequestedBy, &a.DecidedBy, &a.DecidedAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) DecideApproval(ctx context.Context, id, status, decidedBy string) error {
	_, err := s.pool.Exec(ctx, `UPDATE approvals SET status=$2, decided_by=$3, decided_at=now() WHERE id=$1`,
		id, status, decidedBy)
	return err
}

func (s *Store) ApprovalsForRun(ctx context.Context, runID string) ([]model.Approval, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, tool_call_id, tool, arguments, risk, reason, status, requested_by, decided_by, decided_at, created_at
	    FROM approvals WHERE run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Approval
	for rows.Next() {
		var a model.Approval
		if err := rows.Scan(&a.ID, &a.RunID, &a.ToolCallID, &a.Tool, &a.Arguments, &a.Risk,
			&a.Reason, &a.Status, &a.RequestedBy, &a.DecidedBy, &a.DecidedAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// PendingApproval returns the pending approval blocking a run, if any.
func (s *Store) PendingApproval(ctx context.Context, runID string) (*model.Approval, error) {
	var a model.Approval
	err := s.pool.QueryRow(ctx, `SELECT id, run_id, tool_call_id, tool, arguments, risk, reason, status, requested_by, decided_by, decided_at, created_at
	    FROM approvals WHERE run_id=$1 AND status='pending' ORDER BY created_at DESC LIMIT 1`, runID).
		Scan(&a.ID, &a.RunID, &a.ToolCallID, &a.Tool, &a.Arguments, &a.Risk,
			&a.Reason, &a.Status, &a.RequestedBy, &a.DecidedBy, &a.DecidedAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// LatestApproval returns the most recent approval of any status for a run.
// Resume uses this because the human decision is persisted BEFORE resume is
// triggered, so the blocking approval is no longer 'pending'.
func (s *Store) LatestApproval(ctx context.Context, runID string) (*model.Approval, error) {
	var a model.Approval
	err := s.pool.QueryRow(ctx, `SELECT id, run_id, tool_call_id, tool, arguments, risk, reason, status, requested_by, decided_by, decided_at, created_at
	    FROM approvals WHERE run_id=$1 ORDER BY created_at DESC LIMIT 1`, runID).
		Scan(&a.ID, &a.RunID, &a.ToolCallID, &a.Tool, &a.Arguments, &a.Risk,
			&a.Reason, &a.Status, &a.RequestedBy, &a.DecidedBy, &a.DecidedAt, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ---------------------------------------------------------------- model usage

func (s *Store) RecordUsage(ctx context.Context, runID string, rec llm.UsageRecord) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO model_usage
	    (run_id, provider, model, task_type, input_tokens, output_tokens, latency_ms, estimated_cost, status, retry_count, error)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		nullIfEmpty(runID), rec.Provider, rec.Model, string(rec.TaskType), rec.InputTokens,
		rec.OutputTokens, rec.LatencyMS, rec.CostCents, orDefault(rec.Status, "ok"), rec.RetryCount, rec.Error)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `UPDATE agent_runs SET total_tokens = total_tokens + $2,
	    total_cost_cents = total_cost_cents + $3 WHERE id=$1`,
		runID, rec.InputTokens+rec.OutputTokens, rec.CostCents)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (s *Store) ModelUsage(ctx context.Context, runID string) ([]model.ModelUsage, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, eval_run_id, provider, model, task_type,
	    input_tokens, output_tokens, latency_ms, estimated_cost, status, retry_count, error, created_at
	    FROM model_usage WHERE run_id=$1 ORDER BY id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ModelUsage
	for rows.Next() {
		var m model.ModelUsage
		if err := rows.Scan(&m.ID, &m.RunID, &m.EvalRunID, &m.Provider, &m.Model, &m.TaskType,
			&m.InputTokens, &m.OutputTokens, &m.LatencyMS, &m.EstimatedCost, &m.Status,
			&m.RetryCount, &m.Error, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

var _ = context.Background
