package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/runs"
)

// Runner is the optional HermesAgentRunner. It implements the SAME
// agent.Runner contract as the native runner: IncidentGraph keeps owning the
// run lifecycle, persistence, tool policy and approvals — Hermes only drives
// the investigation loop remotely using our tools through incidentgraph-mcp.
//
// Contract with the Hermes side (defined by us, not forked):
//
//	POST /api/runs/start            -> {"session_id","status"}
//	GET  /api/runs/{session}        -> {"status":"running|completed|failed|cancelled",
//	                                    "events":[{"type": "...", "payload": {...}}]}
//	POST /api/runs/{session}/stop   -> {}
//
// If Hermes is unreachable the run fails explicitly — we never silently fall
// back to another engine.
type Runner struct {
	client *Client
	runs   *runs.Store
	log    *observability.Logger

	// MCPURL is the incidentgraph-mcp server URL handed to Hermes so its
	// tool calls flow back through OUR policy engine and DurableMCP.
	MCPURL string
	// Tools is the explicit allowlist exposed to the Hermes session.
	Tools []string
}

func NewRunner(client *Client, store *runs.Store, mcpURL string, tools []string) *Runner {
	return &Runner{
		client: client,
		runs:   store,
		log:    observability.New("hermes-runner"),
		MCPURL: mcpURL,
		Tools:  tools,
	}
}

var _ interface {
	Start(ctx context.Context, runID string) error
	Resume(ctx context.Context, runID string) error
	Cancel(ctx context.Context, runID string) error
} = (*Runner)(nil)

func (r *Runner) Start(ctx context.Context, runID string) error {
	return r.drive(ctx, runID, false)
}

// Resume continues an existing run (approval decisions are already persisted;
// Hermes re-drives from our persisted state).
func (r *Runner) Resume(ctx context.Context, runID string) error {
	return r.drive(ctx, runID, true)
}

func (r *Runner) Cancel(ctx context.Context, runID string) error {
	run, err := r.runs.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	if sess := r.sessionRef(run); sess != "" {
		_ = r.client.Stop(ctx, sess)
	}
	return r.runs.FinishRun(ctx, runID, model.RunCancelled, "CANCELLED", "")
}

func (r *Runner) sessionRef(run *model.AgentRun) string {
	if run == nil || run.AgentBackend != "hermes" {
		return ""
	}
	return run.TerminationReason // session id stashed while driving (see below)
}

type sessionState struct {
	Status string `json:"status"`
	Events []struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	} `json:"events"`
}

func (r *Runner) drive(ctx context.Context, runID string, resume bool) error {
	run, err := r.runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	if !resume && run.Status != model.RunRunning {
		return fmt.Errorf("run %s is %s; only running runs can start", runID, run.Status)
	}
	if err := r.runs.SetPhase(ctx, runID, "plan"); err != nil {
		return err
	}
	_, _ = r.runs.AppendEvent(ctx, runID, "phase_entered", map[string]any{"phase": "plan", "backend": "hermes"})
	_ = r.runs.AddStep(ctx, model.AgentStep{
		RunID: runID, StepType: "hermes_session",
		StructuredInput: marshalJSON(map[string]any{"resume": resume, "mcp_server": r.MCPURL, "tools": r.Tools}),
	})

	inc, _ := r.runs.GetIncident(ctx, run.IncidentID)
	task := ""
	if inc != nil {
		task = inc.Title + ": " + inc.Description
	}
	resp, err := r.client.Start(ctx, StartRequest{
		RunID: runID, IncidentID: run.IncidentID, Task: task,
		MCPServer: r.MCPURL, Tools: r.Tools,
	})
	if err != nil {
		// explicit degraded failure — never a silent fallback to native
		msg := "hermes unavailable: " + err.Error()
		_ = r.runs.FinishRun(ctx, runID, model.RunFailed, "BACKEND_UNAVAILABLE", msg)
		_, _ = r.runs.AppendEvent(ctx, runID, "completed", map[string]any{"status": model.RunFailed, "termination_reason": "BACKEND_UNAVAILABLE"})
		return fmt.Errorf("%s", msg)
	}
	_, _ = r.runs.AppendEvent(ctx, runID, "hermes_session_started", map[string]any{"session_id": resp.SessionID})

	return r.pollUntilDone(ctx, runID, resp.SessionID)
}

func (r *Runner) pollUntilDone(ctx context.Context, runID, sessionID string) error {
	deadline := time.Now().Add(30 * time.Minute)
	seen := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
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

func marshalJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func emptyObj(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}
