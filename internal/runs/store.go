// Package runs persists agent-run lifecycle state: incidents, runs, steps,
// tool calls (+events), approvals, model usage and the SSE replay log.
package runs

import (
	"context"
	"encoding/json"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool} }

// ---------------------------------------------------------------- incidents

func (s *Store) CreateIncident(ctx context.Context, i model.Incident) error {
	if i.ID == "" {
		i.ID = model.New()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO incidents (id, title, description, service, severity, status)
	    VALUES ($1,$2,$3,$4,$5,$6)`, i.ID, i.Title, i.Description, i.Service, i.Severity, orDefault(i.Status, "open"))
	return err
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

const incidentCols = `id, title, description, service, severity, status, created_at`

func scanIncident(row interface{ Scan(...any) error }) (model.Incident, error) {
	var i model.Incident
	err := row.Scan(&i.ID, &i.Title, &i.Description, &i.Service, &i.Severity, &i.Status, &i.CreatedAt)
	return i, err
}

func (s *Store) GetIncident(ctx context.Context, id string) (*model.Incident, error) {
	i, err := scanIncident(s.pool.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	return &i, nil
}

func (s *Store) ListIncidents(ctx context.Context, limit int) ([]model.Incident, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Incident
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- runs

func (s *Store) CreateRun(ctx context.Context, r model.AgentRun) error {
	if r.ID == "" {
		r.ID = model.New()
	}
	if r.Status == "" {
		r.Status = model.RunRunning
	}
	if r.CurrentPhase == "" {
		r.CurrentPhase = "received"
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_runs (id, incident_id, agent_backend, model, status, current_phase)
	    VALUES ($1,$2,$3,$4,$5,$6)`,
		r.ID, r.IncidentID, r.AgentBackend, r.Model, r.Status, r.CurrentPhase)
	return err
}

const runCols = `id, incident_id, agent_backend, model, status, current_phase, termination_reason,
	total_tokens, total_cost_cents, latency_ms, error, started_at, completed_at`

func scanRun(row interface{ Scan(...any) error }) (model.AgentRun, error) {
	var r model.AgentRun
	var completed *model.TimeStamp
	err := row.Scan(&r.ID, &r.IncidentID, &r.AgentBackend, &r.Model, &r.Status, &r.CurrentPhase,
		&r.TerminationReason, &r.TotalTokens, &r.TotalCostCents, &r.LatencyMS, &r.Error,
		&r.StartedAt, &completed)
	r.CompletedAt = completed
	return r, err
}

func (s *Store) GetRun(ctx context.Context, id string) (*model.AgentRun, error) {
	r, err := scanRun(s.pool.QueryRow(ctx, `SELECT `+runCols+` FROM agent_runs WHERE id=$1`, id))
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) ListRuns(ctx context.Context, incidentID string, limit int) ([]model.AgentRun, error) {
	q := `SELECT ` + runCols + ` FROM agent_runs`
	args := []any{}
	if incidentID != "" {
		q += ` WHERE incident_id=$1`
		args = append(args, incidentID)
	}
	args = append(args, limit)
	q += ` ORDER BY started_at DESC LIMIT $` + itoa(len(args))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActiveRuns returns non-terminal runs (for resume-after-restart).
func (s *Store) ActiveRuns(ctx context.Context) ([]model.AgentRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+runCols+` FROM agent_runs WHERE status IN ($1,$2) ORDER BY started_at`,
		model.RunRunning, model.RunNeedsApproval)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetPhase advances current_phase without a fence (non-driving callers).
// Drivers must use SetPhaseFenced.
func (s *Store) SetPhase(ctx context.Context, runID, phase string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_runs SET current_phase=$2 WHERE id=$1`, runID, phase)
	return err
}

// ClaimableRunIDs returns runnable runs with no valid lease (crashed drivers,
// freshly approved resumes). Drivers claim them through ClaimRun/Resume.
func (s *Store) ClaimableRunIDs(ctx context.Context, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM agent_runs
	    WHERE status=$1 AND (lease_expires_at IS NULL OR lease_expires_at < now())
	    ORDER BY started_at LIMIT $2`, model.RunRunning, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SetExternalSession persists the external engine session identity
// (e.g. Hermes session id) on the run row.
func (s *Store) SetExternalSession(ctx context.Context, runID, backend, sessionID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agent_runs SET external_backend=$2, external_session_id=$3 WHERE id=$1`,
		runID, backend, sessionID)
	return err
}

// ExternalSession returns the persisted external session for the run, if any.
func (s *Store) ExternalSession(ctx context.Context, runID string) (backend, sessionID string, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT COALESCE(external_backend,''), COALESCE(external_session_id,'') FROM agent_runs WHERE id=$1`,
		runID).Scan(&backend, &sessionID)
	return
}

// late finish/cancel from a stale driver.
var terminalStatuses = []string{model.RunComplete, model.RunFailed, model.RunCancelled}

// FinishRun records an UNCONDITIONAL guarded terminal transition. It is the
// operator path (Cancel) and recovery path: it intentionally bypasses leases
// because human/operator authority supersedes them, but it can never overwrite
// an already-terminal outcome. Drivers must use FinishRunFenced.
func (s *Store) FinishRun(ctx context.Context, runID, status, terminationReason, errMsg string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_runs SET status=$2, termination_reason=$3, error=$4,
	    completed_at=COALESCE(completed_at, CASE WHEN $2 IN ('complete','failed','cancelled') THEN now() ELSE completed_at END),
	    latency_ms = GREATEST(0, EXTRACT(EPOCH FROM (now()-started_at))*1000)::bigint
	    WHERE id=$1 AND status <> ALL($5::text[])`,
		runID, status, terminationReason, errMsg, terminalStatuses)
	return err
}

func (s *Store) SetModel(ctx context.Context, runID, m string) error {
	_, err := s.pool.Exec(ctx, `UPDATE agent_runs SET model=$2 WHERE id=$1`, runID, m)
	return err
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ---------------------------------------------------------------- steps

func (s *Store) AddStep(ctx context.Context, step model.AgentStep) error {
	if step.ID == "" {
		step.ID = model.New()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_steps
	    (id, run_id, step_number, step_type, state, structured_input, structured_output, context_manifest, latency_ms, error)
	    VALUES ($1,$2,(SELECT COALESCE(MAX(step_number),0)+1 FROM agent_steps WHERE run_id=$2),$3,$4,$5,$6,$7,$8,$9)`,
		step.ID, step.RunID, step.StepType, orDefault(step.State, "succeeded"),
		emptyJSON(step.StructuredInput), emptyJSON(step.StructuredOutput),
		emptyJSONArr(step.ContextManifest), step.LatencyMS, step.Error)
	return err
}

func emptyJSON(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(`{}`)
	}
	return b
}
func emptyJSONArr(b json.RawMessage) json.RawMessage {
	if len(b) == 0 {
		return json.RawMessage(`[]`)
	}
	return b
}

func (s *Store) Steps(ctx context.Context, runID string) ([]model.AgentStep, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, step_number, step_type, state, structured_input, structured_output, context_manifest, latency_ms, error, created_at
	    FROM agent_steps WHERE run_id=$1 ORDER BY step_number`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AgentStep
	for rows.Next() {
		var st model.AgentStep
		if err := rows.Scan(&st.ID, &st.RunID, &st.StepNumber, &st.StepType, &st.State,
			&st.StructuredInput, &st.StructuredOutput, &st.ContextManifest, &st.LatencyMS,
			&st.Error, &st.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// LastStep returns the most recent step of a given type (resume support).
func (s *Store) LastStepOfType(ctx context.Context, runID, stepType string) (*model.AgentStep, error) {
	var st model.AgentStep
	err := s.pool.QueryRow(ctx, `SELECT id, run_id, step_number, step_type, state, structured_input, structured_output, context_manifest, latency_ms, error, created_at
	    FROM agent_steps WHERE run_id=$1 AND step_type=$2 ORDER BY step_number DESC LIMIT 1`,
		runID, stepType).Scan(&st.ID, &st.RunID, &st.StepNumber, &st.StepType, &st.State,
		&st.StructuredInput, &st.StructuredOutput, &st.ContextManifest, &st.LatencyMS, &st.Error, &st.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &st, nil
}

// ---------------------------------------------------------------- events (SSE log)

func (s *Store) AppendEvent(ctx context.Context, runID, eventType string, payload any) (int64, error) {
	b, _ := json.Marshal(payload)
	var seq int64
	err := s.pool.QueryRow(ctx, `INSERT INTO run_events (run_id, event_type, payload) VALUES ($1,$2,$3) RETURNING seq`,
		runID, eventType, b).Scan(&seq)
	return seq, err
}

func (s *Store) EventsSince(ctx context.Context, runID string, sinceSeq int64) ([]model.RunEvent, error) {
	rows, err := s.pool.Query(ctx, `SELECT seq, run_id, event_type, payload, created_at
	    FROM run_events WHERE run_id=$1 AND seq > $2 ORDER BY seq`, runID, sinceSeq)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RunEvent
	for rows.Next() {
		var e model.RunEvent
		if err := rows.Scan(&e.Seq, &e.RunID, &e.EventType, &e.Payload, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
