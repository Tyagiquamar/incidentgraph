package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
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

// defaultOwner builds a process-unique lease owner identity
// ("<hostname>-<random>") so two drivers can never share an identity.
func defaultOwner() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	var b [6]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(host) + "-" + hex.EncodeToString(b[:]) + "-" + fmt.Sprintf("%d", os.Getpid()) + "-" + runtime.GOOS
}

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
	// LeaseOwner identifies this driver process; LeaseTTL is the claim TTL.
	// The heartbeat renews at TTL/3 (minimum 1s).
	LeaseOwner string
	LeaseTTL   time.Duration

	Log *observability.Logger
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
	// driverID is the stable lease owner identity of this process.
	driverID string
	ttl      time.Duration

	mu      sync.Mutex
	cancels map[string]bool // in-flight cancellation requests by run ID
}

func NewNative(deps Deps) *NativeRunner {
	if deps.Log == nil {
		deps.Log = observability.New("native-runner")
	}
	if deps.LeaseTTL <= 0 {
		deps.LeaseTTL = 60 * time.Second
	}
	if deps.LeaseOwner == "" {
		deps.LeaseOwner = defaultOwner()
	}
	return &NativeRunner{
		deps:     deps,
		driverID: deps.LeaseOwner,
		ttl:      deps.LeaseTTL,
		cancels:  map[string]bool{},
	}
}

// ---------------------------------------------------------------- lifecycle
//
// SINGLE OWNERSHIP PATH: Start/Resume acquire the fenced run lease themselves
// (ClaimRun). Workers/schedulers only decide WHEN to attempt a resume — they
// never hold the driving lease. A heartbeat renews at TTL/3; losing ownership
// cancels the local drive immediately and the stale driver exits without
// mutating persisted state.

func (r *NativeRunner) Start(ctx context.Context, runID string) error {
	run, err := r.deps.Runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	if run.Status != model.RunRunning {
		return fmt.Errorf("run %s is %s; only running runs can start", runID, run.Status)
	}
	return r.driveClaimed(ctx, run)
}

func (r *NativeRunner) Resume(ctx context.Context, runID string) error {
	run, err := r.deps.Runs.GetRun(ctx, runID)
	if err != nil {
		return fmt.Errorf("load run: %w", err)
	}
	switch run.Status {
	case model.RunRunning, model.RunNeedsApproval:
	default:
		return fmt.Errorf("run %s is %s; only running runs can resume", runID, run.Status)
	}
	return r.driveClaimed(ctx, run)
}

// driveClaimed acquires the lease, arms the heartbeat, then drives. It is the
// single entry point for actually executing a run.
func (r *NativeRunner) driveClaimed(ctx context.Context, run *model.AgentRun) error {
	lease, err := r.deps.Runs.ClaimRun(ctx, run.ID, r.driverID, r.ttl)
	if err != nil {
		if errors.Is(err, runs.ErrNotClaimable) {
			return fmt.Errorf("run %s is leased to another driver", run.ID)
		}
		return fmt.Errorf("claim run: %w", err)
	}

	driveCtx, cancel := context.WithCancel(ctx)
	defer cancel() // also stops the heartbeat goroutine
	go r.heartbeat(driveCtx, cancel, *lease)

	r.emit(driveCtx, run.ID, "driver_attached",
		map[string]any{"owner": r.driverID, "generation": lease.Generation})
	err = r.drive(driveCtx, run, *lease)
	// Release only if we still own the lease (pause/finish already released).
	if vl, verr := r.deps.Runs.VerifyLease(context.Background(), *lease); verr == nil && vl {
		_ = r.deps.Runs.ReleaseLease(context.Background(), *lease)
	}
	return err
}

// heartbeat renews the lease while the drive loop works. Losing ownership
// cancels the drive context so the stale driver stops immediately.
func (r *NativeRunner) heartbeat(ctx context.Context, cancel context.CancelFunc, lease runs.Lease) {
	interval := r.ttl / 3
	if interval < time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, ok, err := r.deps.Runs.RenewLease(ctx, lease, r.ttl)
			if err != nil {
				r.deps.Log.Warn("lease renewal failed", observability.F{"run_id": lease.RunID, "error": err.Error()})
				continue // transient DB issues shouldn't kill a healthy owner
			}
			if !ok {
				r.deps.Log.Warn("lease lost; aborting stale driver",
					observability.F{"run_id": lease.RunID, "owner": lease.Owner, "generation": lease.Generation})
				cancel()
				return
			}
		}
	}
}

// Cancel marks the run cancelled. This is the OPERATOR path: it intentionally
// bypasses leases (human authority supersedes them) but is guarded so a late
// write can never resurrect a cancelled run. In-flight drivers observe the
// persisted status at their next phase boundary.
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

// staleLeaseError aborts the drive loop quietly: this driver lost ownership
// and must NOT mutate the run further. The current owner is authoritative.
type staleLeaseError struct{ runID string }

func (e *staleLeaseError) Error() string {
	return "stale lease; aborting driver for run " + e.runID
}

// drive advances the persisted state machine until terminal or paused.
// Every iteration verifies lease ownership (fencing); every persisted write
// goes through fenced variants. Losing the lease terminates THIS driver only.
func (r *NativeRunner) drive(ctx context.Context, run *model.AgentRun, lease runs.Lease) error {
	// Resolve a persisted approval decision under our fresh lease before any
	// phase runs (crash-recovery path: decision was made by a human earlier).
	if err := r.resolvePersistedApproval(ctx, run.ID); err != nil {
		return err
	}

	for i := 0; i < r.deps.Budgets.MaxSteps*3; i++ { // hard outer guard
		// cancellation: in-process flag plus persisted status (covers operator
		// cancel issued from another process mid-drive)
		if r.cancelRequested(run.ID) {
			return nil // status already persisted as cancelled; do not overwrite
		}
		// refresh persisted state every iteration FIRST: keeps budget checks
		// honest, detects cross-process cancel, and recognizes our own fenced
		// finish (which intentionally releases our lease) as a clean exit.
		fresh, err := r.deps.Runs.GetRun(ctx, run.ID)
		if err != nil {
			r.deps.Log.Warn("run refresh failed", observability.F{"run_id": run.ID, "error": err.Error()})
		} else if fresh != nil {
			switch fresh.Status {
			case model.RunCancelled, model.RunComplete, model.RunFailed:
				return nil // terminal (operator cancel, our own finish, recovery race)
			case model.RunNeedsApproval:
				return nil // paused (our own PauseForApproval released the lease)
			}
			fresh.CurrentPhase = run.CurrentPhase // phase transitions are driven locally
			run = fresh
		}
		// fencing: verify we still own this generation before mutating anything.
		// Reaching here while unleased means ANOTHER driver reclaimed the run:
		// terminate without touching anything (new owner is authoritative).
		owned, err := r.deps.Runs.VerifyLease(ctx, lease)
		if err != nil {
			r.deps.Log.Warn("lease verify failed", observability.F{"run_id": run.ID, "error": err.Error()})
		} else if !owned || ctx.Err() != nil {
			r.emit(context.Background(), run.ID, "driver_detached_stale_lease",
				map[string]any{"owner": lease.Owner, "generation": lease.Generation})
			return &staleLeaseError{runID: run.ID}
		}
		// budget checks between phases
		if run.TotalTokens > int64(r.deps.Budgets.MaxTokenBudget) {
			return r.finish(ctx, lease, model.RunFailed, "MAX_TOKENS", "token budget exhausted")
		}
		if run.TotalCostCents > r.deps.Budgets.MaxCostCents {
			return r.finish(ctx, lease, model.RunFailed, "MAX_COST", "cost budget exhausted")
		}
		var phaseErr error
		switch run.CurrentPhase {
		case "received":
			phaseErr = r.setPhase(ctx, lease, run, phaseContextBuild)
		case phaseContextBuild:
			phaseErr = r.phaseContextBuild(ctx, run, lease)
		case phasePlan:
			phaseErr = r.phasePlan(ctx, run, lease)
		case phaseInvestigate:
			phaseErr = r.phaseInvestigate(ctx, run, lease)
		case phaseHypothesis:
			phaseErr = r.phaseHypothesis(ctx, run, lease)
		case phaseVerify:
			phaseErr = r.phaseVerify(ctx, run, lease)
		case phaseSynthesize:
			phaseErr = r.phaseSynthesize(ctx, run, lease)
		case phaseComplete:
			return r.finish(ctx, lease, model.RunComplete, "SUCCESS", "")
		default:
			return r.finish(ctx, lease, model.RunFailed, "FAILED", "unknown phase "+run.CurrentPhase)
		}
		if phaseErr != nil {
			var sl *staleLeaseError
			if errors.As(phaseErr, &sl) {
				return sl // propagate quietly; driveClaimed will not release
			}
			if pe, ok := phaseErr.(*pausedError); ok {
				_ = pe // PauseForApproval already persisted + released the lease
				return nil
			}
			r.deps.Log.Error("phase failed", observability.F{"run_id": run.ID, "phase": run.CurrentPhase, "error": phaseErr.Error()})
			return r.finish(ctx, lease, model.RunFailed, "FAILED", phaseErr.Error())
		}
		continue
	}
	return r.finish(ctx, lease, model.RunFailed, "MAX_STEPS", "state machine did not converge")
}

func (r *NativeRunner) setPhase(ctx context.Context, lease runs.Lease, run *model.AgentRun, phase string) error {
	run.CurrentPhase = phase
	if err := r.deps.Runs.SetPhaseFenced(ctx, lease, phase); err != nil {
		if errors.Is(err, runs.ErrStaleLease) {
			return &staleLeaseError{runID: run.ID}
		}
		return err
	}
	r.emit(ctx, run.ID, "phase_entered", map[string]any{"phase": phase})
	return nil
}

// finish persists the terminal outcome through the FENCED write so a stale
// driver can never finish a run reclaimed by another owner.
func (r *NativeRunner) finish(ctx context.Context, lease runs.Lease, status, reason, errMsg string) error {
	if err := r.deps.Runs.FinishRunFenced(ctx, lease, status, reason, errMsg); err != nil {
		if errors.Is(err, runs.ErrStaleLease) {
			return &staleLeaseError{runID: lease.RunID}
		}
		return err
	}
	r.emit(ctx, lease.RunID, "completed", map[string]any{"status": status, "termination_reason": reason, "error": errMsg})
	return nil
}

// resolvePersistedApproval applies an already-decided approval to the tool
// call state before driving continues (crash recovery after DecideApprovalTx).
func (r *NativeRunner) resolvePersistedApproval(ctx context.Context, runID string) error {
	pa, err := r.deps.Runs.LatestApproval(ctx, runID)
	if err != nil || pa == nil {
		return nil
	}
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
	return nil
}

// pausedError signals the run was persisted as needs_approval (lease released).
type pausedError struct{}

func (*pausedError) Error() string { return "paused: needs approval" }

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

func paDecidedBy(pa *model.Approval) string {
	if pa == nil || pa.DecidedBy == "" {
		return ""
	}
	return " (" + pa.DecidedBy + ")"
}

// Owner returns this driver process's lease-owner identity.
func (r *NativeRunner) Owner() string { return r.driverID }
