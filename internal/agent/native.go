package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/durablemcp"
	"github.com/incidentgraph/incidentgraph/internal/evidence"
	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/memory"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/incidentgraph/incidentgraph/internal/tools"
)

// Deps bundles everything the native runner needs.
type Deps struct {
	Runs      *runs.Store
	Policy    *policy.Engine
	Tools     *tools.Registry
	Evidence  *evidence.Store
	Memory    *memory.Store
	Retrieval *retrieval.Store
	LLM       *llm.Router
	Security  *security.Store
	Durable   *durablemcp.Client // may be nil => durable path unavailable

	Budgets Budgets
	Log     *observability.Logger
}

type Budgets struct {
	MaxSteps           int
	MaxToolCalls       int
	MaxSameToolRepeats int
	MaxTokenBudget     int
	MaxCostCents       float64
}

type NativeRunner struct {
	deps Deps

	mu      sync.Mutex
	cancels map[string]bool // in-flight cancellation requests by run ID
}

func NewNative(deps Deps) *NativeRunner {
	if deps.Log == nil {
		deps.Log = observability.New("native-runner")
	}
	return &NativeRunner{deps: deps, cancels: map[string]bool{}}
}

// ---------------------------------------------------------------- lifecycle

func (r *NativeRunner) Start(ctx context.Context, runID string) error {
	run, err := r.deps.Runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	r.emit(ctx, runID, "phase_entered", map[string]any{"phase": "received"})
	return r.drive(ctx, run)
}

func (r *NativeRunner) Resume(ctx context.Context, runID string) error {
	run, err := r.deps.Runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	if run.Status != model.RunNeedsApproval && run.Status != model.RunRunning {
		return fmt.Errorf("run %s is %s; only paused/running runs can resume", runID, run.Status)
	}
	// If paused on an approval, resolve it before driving. The decision is
	// already persisted at this point (approve/reject happens before resume),
	// so we look at the latest approval regardless of status and act on the
	// tool call only if it has not reached a terminal state yet.
	if pa, _ := r.deps.Runs.LatestApproval(ctx, runID); pa != nil {
		switch pa.Status {
		case "approved":
			if pa.ToolCallID != nil {
				tc, err := r.deps.Runs.GetToolCall(ctx, *pa.ToolCallID)
				if err == nil && tc != nil && (tc.Status == "approved" || tc.Status == "pending") {
					_ = r.executeApproved(ctx, runID, tc)
				}
			}
		case "rejected":
			if pa.ToolCallID != nil {
				tc, err := r.deps.Runs.GetToolCall(ctx, *pa.ToolCallID)
				if err == nil && tc != nil && (tc.Status == "approved" || tc.Status == "pending") {
					_ = r.deps.Runs.CompleteToolCall(ctx, tc.ID, "denied", "", 0, "rejected by operator "+paDecidedBy(pa))
				}
			}
			_ = r.deps.Memory.PutWorking(ctx, runID, "last_approval", "A proposed write action was rejected by a human operator. Do not re-propose it without new evidence.")
		}
	}
	_ = r.deps.Runs.SetPhase(ctx, runID, run.CurrentPhase)
	return r.drive(ctx, run)
}

// Cancel marks the run cancelled. Both an in-process flag (observed between
// phases by any in-flight drive loop) and the persisted status are set; the
// persisted write is guarded so a late finish from a stale driver can never
// resurrect a cancelled run.
func (r *NativeRunner) Cancel(ctx context.Context, runID string) error {
	r.mu.Lock()
	r.cancels[runID] = true
	r.mu.Unlock()
	return r.deps.Runs.FinishRun(ctx, runID, model.RunCancelled, "CANCELLED", "")
}

func (r *NativeRunner) cancelRequested(runID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancels[runID]
}

// emit persists an event BEFORE streaming (SSE replays from this log).
func (r *NativeRunner) emit(ctx context.Context, runID, eventType string, payload any) {
	if _, err := r.deps.Runs.AppendEvent(ctx, runID, eventType, payload); err != nil {
		r.deps.Log.Error("append event failed", observability.F{"run_id": runID, "error": err.Error()})
	}
}

// ---------------------------------------------------------------- drive loop

const (
	phaseContextBuild = "context_build"
	phasePlan         = "plan"
	phaseInvestigate  = "investigate"
	phaseHypothesis   = "hypothesis"
	phaseVerify       = "verify"
	phaseSynthesize   = "synthesize"
	phaseComplete     = "complete"
)

// drive advances the persisted state machine until terminal or paused.
func (r *NativeRunner) drive(ctx context.Context, run *model.AgentRun) error {
	for i := 0; i < r.deps.Budgets.MaxSteps*3; i++ { // hard outer guard
		// cancellation: in-process flag plus persisted status (covers
		// cancellation issued from another process/goroutine mid-drive)
		if r.cancelRequested(run.ID) {
			return nil // status already persisted as cancelled; do not overwrite
		}
		if err := ctx.Err(); err != nil {
			return r.finish(ctx, run.ID, model.RunCancelled, "CANCELLED", "context cancelled")
		}
		// refresh persisted state every iteration: keeps budget checks honest
		// (token/cost totals live in Postgres) and detects cross-process cancel.
		if fresh, err := r.deps.Runs.GetRun(ctx, run.ID); err == nil && fresh != nil {
			switch fresh.Status {
			case model.RunCancelled, model.RunComplete, model.RunFailed:
				return nil // someone else finished this run (cancel/recovery race)
			}
			fresh.CurrentPhase = run.CurrentPhase // phase transitions are driven locally
			run = fresh
		}
		// budget checks between phases
		if run.TotalTokens > int64(r.deps.Budgets.MaxTokenBudget) {
			return r.finish(ctx, run.ID, model.RunFailed, "MAX_TOKENS", "token budget exhausted")
		}
		if run.TotalCostCents > r.deps.Budgets.MaxCostCents {
			return r.finish(ctx, run.ID, model.RunFailed, "MAX_COST", "cost budget exhausted")
		}
		var err error
		switch run.CurrentPhase {
		case "received":
			err = r.setPhase(ctx, run, phaseContextBuild)
		case phaseContextBuild:
			err = r.phaseContextBuild(ctx, run)
		case phasePlan:
			err = r.phasePlan(ctx, run)
		case phaseInvestigate:
			err = r.phaseInvestigate(ctx, run)
		case phaseHypothesis:
			err = r.phaseHypothesis(ctx, run)
		case phaseVerify:
			err = r.phaseVerify(ctx, run)
		case phaseSynthesize:
			err = r.phaseSynthesize(ctx, run)
		case phaseComplete:
			return r.finish(ctx, run.ID, model.RunComplete, "SUCCESS", "")
		default:
			return r.finish(ctx, run.ID, model.RunFailed, "FAILED", "unknown phase "+run.CurrentPhase)
		}
		if err != nil {
			if pe, ok := err.(*pausedError); ok {
				_ = pe // run already persisted as needs_approval
				return nil
			}
			r.deps.Log.Error("phase failed", observability.F{"run_id": run.ID, "phase": run.CurrentPhase, "error": err.Error()})
			return r.finish(ctx, run.ID, model.RunFailed, "FAILED", err.Error())
		}
		continue
	}
	return r.finish(ctx, run.ID, model.RunFailed, "MAX_STEPS", "state machine did not converge")
}

func (r *NativeRunner) setPhase(ctx context.Context, run *model.AgentRun, phase string) error {
	run.CurrentPhase = phase
	if err := r.deps.Runs.SetPhase(ctx, run.ID, phase); err != nil {
		return err
	}
	r.emit(ctx, run.ID, "phase_entered", map[string]any{"phase": phase})
	return nil
}

// finish persists the terminal outcome. FinishRun is a guarded no-op for runs
// already terminal, so stale drivers cannot overwrite a cancel/complete.
func (r *NativeRunner) finish(ctx context.Context, runID, status, reason, errMsg string) error {
	if err := r.deps.Runs.FinishRun(ctx, runID, status, reason, errMsg); err != nil {
		return err
	}
	r.emit(ctx, runID, "completed", map[string]any{"status": status, "termination_reason": reason, "error": errMsg})
	return nil
}

// pausedError signals the run was persisted as needs_approval.
type pausedError struct{}

func (*pausedError) Error() string { return "paused: needs approval" }

func paDecidedBy(pa *model.Approval) string {
	if pa == nil || pa.DecidedBy == "" {
		return ""
	}
	return " (" + pa.DecidedBy + ")"
}

// ---------------------------------------------------------------- helpers

func (r *NativeRunner) incident(ctx context.Context, run *model.AgentRun) (*model.Incident, error) {
	return r.deps.Runs.GetIncident(ctx, run.IncidentID)
}

var stopWords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "of": true, "to": true,
	"in": true, "on": true, "after": true, "from": true, "is": true, "was": true, "increased": true,
	"find": true, "show": true, "likely": true, "root": true, "cause": true, "evidence": true,
}

func keywords(text string, n int) []string {
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
	})
	freq := map[string]int{}
	order := []string{}
	for _, f := range fields {
		if len(f) < 3 || stopWords[f] {
			continue
		}
		if freq[f] == 0 {
			order = append(order, f)
		}
		freq[f]++
	}
	// stable sort by freq desc
	for i := 0; i < len(order); i++ {
		for j := i + 1; j < len(order); j++ {
			if freq[order[j]] > freq[order[i]] {
				order[i], order[j] = order[j], order[i]
			}
		}
	}
	if len(order) > n {
		order = order[:n]
	}
	return order
}

func shortEvidenceID() string { return "E-" + model.New()[:8] }

func marshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func latency(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}
