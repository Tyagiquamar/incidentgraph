package hermes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/runs"
)

// Runner is the optional HermesAgentRunner. It implements the SAME
// agent.Runner contract as the native runner: IncidentGraph keeps owning the
// run lifecycle, persistence, tool policy, approvals and leases — Hermes only
// drives the investigation loop remotely using our tools through
// incidentgraph-mcp.
//
// Session contract with the Hermes side (defined by us, not forked):
//
//	POST /api/runs/start            -> {"session_id","status"}
//	GET  /api/runs/{session}        -> {"status":"running|completed|failed|cancelled",
//	                                    "events":[{"type": "...", "payload": {...}}]}
//	POST /api/runs/{session}/stop   -> {}
//
// Session identity is PERSISTED on the run row (external_backend /
// external_session_id). Resume continues an existing session's event stream;
// it never creates a duplicate session. If no session was ever recorded,
// Resume returns an explicit error instead of silently starting one.
//
// Credential contract: when IncidentGraph starts a Hermes session it passes
// the MCP bearer token out-of-band in the start request ("mcp_auth_token");
// tokens are never logged.
//
// If Hermes is unreachable the run fails explicitly — never a silent fallback
// to another engine.
type Runner struct {
	client *Client
	runs   *runs.Store
	log    *observability.Logger

	MCPURL       string
	MCPAuthToken string // handed to Hermes for incidentgraph-mcp auth
	Tools        []string
	LeaseTTL     time.Duration
	driverID     string
}

func NewRunner(client *Client, store *runs.Store, mcpURL, mcpAuthToken string, tools []string) *Runner {
	host, _ := os.Hostname()
	return &Runner{
		client:       client,
		runs:         store,
		log:          observability.New("hermes-runner"),
		MCPURL:       mcpURL,
		MCPAuthToken: mcpAuthToken,
		Tools:        tools,
		LeaseTTL:     60 * time.Second,
		driverID:     "hermes-" + host,
	}
}

var _ interface {
	Start(ctx context.Context, runID string) error
	Resume(ctx context.Context, runID string) error
	Cancel(ctx context.Context, runID string) error
} = (*Runner)(nil)

// Start begins a NEW Hermes session. Requires a fresh runnable run; refuses
// if a session already exists (that would be a duplicate).
func (r *Runner) Start(ctx context.Context, runID string) error {
	run, err := r.runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	if run.Status != model.RunRunning {
		return fmt.Errorf("run %s is %s; only running runs can start", runID, run.Status)
	}
	_ = run
	if _, _, err := r.runs.ExternalSession(ctx, runID); err == nil {
		if _, sess, serr := r.runs.ExternalSession(ctx, runID); serr == nil && sess != "" {
			return fmt.Errorf("run %s already has a hermes session %q; use Resume", runID[:8], sess[:min(len(sess), 8)])
		}
	}
	return r.startNewSession(ctx, runID)
}

// Resume continues driving an EXISTING persisted session. It never creates a
// new one: without a recorded session id, resuming would mean duplicating an
// entire investigation, so this is an explicit unsupported-recovery error.
func (r *Runner) Resume(ctx context.Context, runID string) error {
	run, err := r.runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	switch run.Status {
	case model.RunRunning, model.RunNeedsApproval:
	default:
		return fmt.Errorf("run %s is %s; only running runs can resume", runID, run.Status)
	}
	_, sessionID, err := r.runs.ExternalSession(ctx, runID)
	if err != nil {
		return fmt.Errorf("load external session: %w", err)
	}
	if sessionID == "" {
		return fmt.Errorf(
			"cannot resume hermes run %s: no persisted session id (crash before session creation); "+
				"start a new run instead of duplicating an unknown session", runID[:8])
	}
	r.log.Info("resuming persisted hermes session", observability.F{"run_id": runID[:8], "session": sessionID})
	return r.pollExistingSession(ctx, runID, sessionID)
}

// Cancel stops the PERSISTED external session (never reads identity from
// termination_reason or any other overloaded field), records remote-stop
// failures as run events, and persists local cancellation. Local cancellation
// proceeds even when the remote stop fails: IncidentGraph state stays
// authoritative, and the failure remains inspectable.
func (r *Runner) Cancel(ctx context.Context, runID string) error {
	backend, sessionID, err := r.runs.ExternalSession(ctx, runID)
	if err != nil {
		return err
	}
	if backend != "hermes" || sessionID == "" {
		// nothing to stop remotely; still persist local cancellation
		return r.finishRun(runID, model.RunCancelled, "CANCELLED", "")
	}
	if err := r.client.Stop(ctx, sessionID); err != nil {
		// record the remote failure explicitly; do NOT hide it
		_, _ = r.runs.AppendEvent(ctx, runID, "hermes_stop_failed",
			map[string]any{"session": sessionID, "error": err.Error()})
		r.log.Warn("hermes remote stop failed; cancelling locally anyway",
			observability.F{"run_id": runID[:8], "error": err.Error()})
	}
	return r.finishRun(runID, model.RunCancelled, "CANCELLED", "")
}

// ---------------------------------------------------------------- internals

func (r *Runner) startNewSession(ctx context.Context, runID string) error {
	lease, err := r.runs.ClaimRun(ctx, runID, r.driverID, r.LeaseTTL)
	if err != nil {
		if errors.Is(err, runs.ErrNotClaimable) {
			return fmt.Errorf("run %s is leased to another driver", runID)
		}
		return fmt.Errorf("claim run: %w", err)
	}

	inc, _ := r.runs.GetIncident(ctx, runID2Incident(ctx, r.runs, runID))
	task := ""
	if inc != nil {
		task = inc.Title + ": " + inc.Description
	}
	resp, err := r.client.Start(ctx, StartRequest{
		RunID:        runID,
		Task:         task,
		MCPServer:    r.MCPURL,
		MCPAuthToken: r.MCPAuthToken,
		Tools:        r.Tools,
	})
	if err != nil {
		_ = r.runs.ReleaseLease(context.Background(), *lease)
		msg := "hermes unavailable: " + err.Error()
		_ = r.finishRun(runID, model.RunFailed, "BACKEND_UNAVAILABLE", msg)
		return errors.New(msg)
	}
	// Persist session identity BEFORE polling: crash recovery depends on it.
	if err := r.runs.SetExternalSession(context.Background(), runID, "hermes", resp.SessionID); err != nil {
		_ = r.runs.ReleaseLease(context.Background(), *lease)
		return fmt.Errorf("persist external session: %w", err)
	}
	_, _ = r.runs.AppendEvent(ctx, runID, "hermes_session_started", map[string]any{"session_id": resp.SessionID})
	_ = r.runs.SetPhase(ctx, runID, "investigate")

	err = r.pollLoop(ctx, runID, resp.SessionID)
	if vl, verr := r.runs.VerifyLease(context.Background(), *lease); verr == nil && vl {
		_ = r.runs.ReleaseLease(context.Background(), *lease)
	}
	return err
}

func (r *Runner) pollExistingSession(ctx context.Context, runID, sessionID string) error {
	lease, err := r.runs.ClaimRun(ctx, runID, r.driverID, r.LeaseTTL)
	if err != nil {
		if errors.Is(err, runs.ErrNotClaimable) {
			return fmt.Errorf("run %s is leased to another driver", runID)
		}
		return fmt.Errorf("claim run: %w", err)
	}
	err = r.pollLoop(ctx, runID, sessionID)
	if vl, verr := r.runs.VerifyLease(context.Background(), *lease); verr == nil && vl {
		_ = r.runs.ReleaseLease(context.Background(), *lease)
	}
	return err
}

func (r *Runner) pollLoop(ctx context.Context, runID, sessionID string) error {
	deadline := time.Now().Add(30 * time.Minute)
	seen := 0
	for {
		var st sessionState
		if err := r.client.SessionStatus(ctx, sessionID, &st); err != nil {
			if time.Now().After(deadline) {
				return r.failRun(runID, "poll failed past deadline: "+err.Error())
			}
			time.Sleep(time.Second)
			continue
		}
		for ; seen < len(st.Events); seen++ {
			ev := st.Events[seen]
			_ = r.runs.AddStep(ctx, model.AgentStep{
				RunID:            runID,
				StepType:         "hermes:" + ev.Type,
				StructuredOutput: emptyObj(ev.Payload),
			})
			_, _ = r.runs.AppendEvent(ctx, runID, "hermes_event", map[string]any{"type": ev.Type})
		}
		switch st.Status {
		case "completed":
			return r.finishRun(runID, model.RunComplete, "SUCCESS", "")
		case "failed":
			return r.finishRun(runID, model.RunFailed, "FAILED", "hermes session failed")
		case "cancelled":
			return r.finishRun(runID, model.RunCancelled, "CANCELLED", "")
		}
		if time.Now().After(deadline) {
			return r.failRun(runID, "hermes session did not terminate in time")
		}
		time.Sleep(750 * time.Millisecond)
	}
}

func (r *Runner) finishRun(runID, status, reason, msg string) error {
	if err := r.runs.FinishRun(context.Background(), runID, status, reason, msg); err != nil {
		return err
	}
	_, _ = r.runs.AppendEvent(context.Background(), runID, "completed",
		map[string]any{"status": status, "termination_reason": reason})
	return nil
}

func (r *Runner) failRun(runID, msg string) error {
	return r.finishRun(runID, model.RunFailed, "FAILED", msg)
}

// runID2Incident loads the incident id of a run via the runs store.
func runID2Incident(ctx context.Context, rs *runs.Store, runID string) string {
	run, err := rs.GetRun(ctx, runID)
	if err != nil {
		return ""
	}
	return run.IncidentID
}

func marshalJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

var _ = marshalJSON

func emptyObj(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sessionState mirrors the Hermes session status payload.
type sessionState struct {
	Status string `json:"status"`
	Events []struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	} `json:"events"`
}
