package runs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/jackc/pgx/v5"
)

// Lease is the proof of ownership a driver holds while mutating a run.
//
// A claim atomically sets lease_owner, increments lease_generation and sets
// lease_expires_at. Renewal only succeeds for the exact (owner, generation)
// pair, so a worker whose lease expired cannot renew, release or fence-write
// after another driver reclaimed the run. The generation acts as a fencing
// token: stale drivers detect loss of ownership at phase boundaries and
// terminate themselves without touching persisted state.
type Lease struct {
	RunID      string
	Owner      string
	Generation int64
	ExpiresAt  time.Time
}

// ErrStaleLease is returned by fenced operations when the caller no longer
// owns the run's current lease generation. Callers must stop driving; the
// current owner remains authoritative and the run state must not be touched.
var ErrStaleLease = errors.New("stale lease: run owned by another driver")

func leaseCols() []any { return nil } // placeholder to keep imports tidy if extended

// ClaimRun leases one specific runnable run (status=running) for driving.
// Returns ErrNotClaimable when another driver holds a valid lease or the run
// is not in a drivable state.
func (s *Store) ClaimRun(ctx context.Context, runID, owner string, ttl time.Duration) (*Lease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var l Lease
	err = tx.QueryRow(ctx, `UPDATE agent_runs
	    SET lease_owner=$3, lease_generation = lease_generation + 1,
	        lease_expires_at = now() + make_interval(secs => $4)
	    WHERE id=$1 AND status=$2 AND (lease_expires_at IS NULL OR lease_expires_at < now())
	    RETURNING id, lease_owner, lease_generation, lease_expires_at`,
		runID, model.RunRunning, owner, int(ttl.Seconds())).
		Scan(&l.RunID, &l.Owner, &l.Generation, &l.ExpiresAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotClaimable
		}
		return nil, err
	}
	return &l, tx.Commit(ctx)
}

// ErrNotClaimable indicates the run could not be leased right now.
var ErrNotClaimable = errors.New("run not claimable")

// ClaimNext atomically leases the oldest runnable unleased/expired run.
// Returns (nil, nil) when nothing is claimable.
func (s *Store) ClaimNext(ctx context.Context, owner string, ttl time.Duration) (*Lease, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var runID string
	err = tx.QueryRow(ctx, `SELECT id FROM agent_runs
	    WHERE status=$1 AND (lease_expires_at IS NULL OR lease_expires_at < now())
	    ORDER BY started_at LIMIT 1 FOR UPDATE SKIP LOCKED`, model.RunRunning).Scan(&runID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	var l Lease
	err = tx.QueryRow(ctx, `UPDATE agent_runs
	    SET lease_owner=$2, lease_generation = lease_generation + 1,
	        lease_expires_at = now() + make_interval(secs => $3)
	    WHERE id=$1
	    RETURNING id, lease_owner, lease_generation, lease_expires_at`,
		runID, owner, int(ttl.Seconds())).
		Scan(&l.RunID, &l.Owner, &l.Generation, &l.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &l, tx.Commit(ctx)
}

// RenewLease extends the caller's lease iff it still owns the exact
// (owner, generation) pair and the run is still running. A false result means
// ownership was lost; the caller MUST abort immediately.
func (s *Store) RenewLease(ctx context.Context, l Lease, ttl time.Duration) (Lease, bool, error) {
	row := s.pool.QueryRow(ctx, `UPDATE agent_runs
	    SET lease_expires_at = now() + make_interval(secs => $4)
	    WHERE id=$1 AND lease_owner=$2 AND lease_generation=$3 AND status=$5
	    RETURNING id, lease_owner, lease_generation, lease_expires_at`,
		l.RunID, l.Owner, l.Generation, int(ttl.Seconds()), model.RunRunning)
	var out Lease
	err := row.Scan(&out.RunID, &out.Owner, &out.Generation, &out.ExpiresAt)
	if err == pgx.ErrNoRows {
		return Lease{}, false, nil
	}
	if err != nil {
		return Lease{}, false, err
	}
	return out, true, nil
}

// ReleaseLease clears the lease ONLY if the caller still owns this exact
// generation. A stale release can never clear a newer owner's lease.
func (s *Store) ReleaseLease(ctx context.Context, l Lease) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_runs
	    SET lease_owner='', lease_expires_at=NULL
	    WHERE id=$1 AND lease_owner=$2 AND lease_generation=$3`,
		l.RunID, l.Owner, l.Generation)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleLease
	}
	return nil
}

// VerifyLease reports whether the caller still owns the run's current
// (owner, generation). Used as a fence at every phase boundary.
func (s *Store) VerifyLease(ctx context.Context, l Lease) (bool, error) {
	var owner string
	var gen int64
	err := s.pool.QueryRow(ctx,
		`SELECT lease_owner, lease_generation FROM agent_runs WHERE id=$1`, l.RunID).
		Scan(&owner, &gen)
	if err != nil {
		return false, err
	}
	return owner == l.Owner && gen == l.Generation, nil
}

// ---------------------------------------------------------------- fenced writes

// SetPhaseFenced advances the phase only for the current lease owner.
func (s *Store) SetPhaseFenced(ctx context.Context, l Lease, phase string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_runs SET current_phase=$3
	    WHERE id=$1 AND lease_owner=$2 AND lease_generation=(
	        SELECT lease_generation FROM agent_runs WHERE id=$1)`,
		l.RunID, l.Owner, phase)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleLease
	}
	return nil
}

// FinishRunFenced records the terminal outcome only for the current lease
// owner. Stale drivers cannot finish a run that was reclaimed or cancelled.
// (Operator Cancel intentionally uses the unfenced guarded FinishRun: human
// authority supersedes leases.)
func (s *Store) FinishRunFenced(ctx context.Context, l Lease, status, terminationReason, errMsg string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_runs SET status=$4, termination_reason=$5, error=$6,
	    completed_at=now(), lease_owner='', lease_expires_at=NULL,
	    latency_ms = GREATEST(0, EXTRACT(EPOCH FROM (now()-started_at))*1000)::bigint
	    WHERE id=$1 AND lease_owner=$2 AND lease_generation=$3 AND status NOT IN ('complete','failed','cancelled')`,
		l.RunID, l.Owner, l.Generation, status, terminationReason, errMsg)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleLease
	}
	return nil
}

// PauseForApproval transitions a RUNNING run into NEEDS_APPROVAL:
//   - completed_at stays NULL (needs_approval is NOT terminal),
//   - termination_reason is cleared (no fake terminal reason),
//   - the lease is released so no driver keeps owning a paused run.
//
// Fenced on the caller's lease; stale callers are rejected.
func (s *Store) PauseForApproval(ctx context.Context, l Lease) error {
	tag, err := s.pool.Exec(ctx, `UPDATE agent_runs
	    SET status=$4, completed_at=NULL, error='', termination_reason='',
	    lease_owner='', lease_expires_at=NULL
	    WHERE id=$1 AND lease_owner=$2 AND lease_generation=$3 AND status='running'`,
		l.RunID, l.Owner, l.Generation, model.RunNeedsApproval)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrStaleLease
	}
	return nil
}

// DecideApprovalTx persists a human decision ATOMICALLY with its effects:
// locks the approval row (requires pending), updates the tool call, and
// transitions the paused run back to 'running' with no active lease — making
// it claimable by the normal scheduler. This is the ONLY path that resumes an
// approval-paused run; drivers then acquire their own fenced lease via
// ClaimRun/Resume. Safe under duplicate/concurrent submissions: the first
// transaction wins, later ones get ErrApprovalAlreadyDecided.
func (s *Store) DecideApprovalTx(ctx context.Context, approvalID, decision, decidedBy string) (*model.Approval, error) {
	if decision != "approved" && decision != "rejected" {
		return nil, fmt.Errorf("invalid approval decision %q", decision)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var a model.Approval
	var callID *string
	var runID string
	var status string
	err = tx.QueryRow(ctx, `SELECT id, run_id, tool_call_id, status FROM approvals WHERE id=$1 FOR UPDATE`,
		approvalID).Scan(&a.ID, &runID, &callID, &status)
	if err != nil {
		return nil, err
	}
	a.RunID = runID
	a.ToolCallID = callID
	if status != "pending" {
		return &a, ErrApprovalAlreadyDecided
	}

	if _, err := tx.Exec(ctx,
		`UPDATE approvals SET status=$2, decided_by=$3, decided_at=now() WHERE id=$1`,
		approvalID, decision, decidedBy); err != nil {
		return nil, err
	}

	switch decision {
	case "approved":
		if callID != nil {
			if _, err := tx.Exec(ctx,
				`UPDATE tool_calls SET policy_decision='allowed', status='approved' WHERE id=$1`, *callID); err != nil {
				return nil, err
			}
		}
	case "rejected":
		if callID != nil {
			if _, err := tx.Exec(ctx,
				`UPDATE tool_calls SET status='denied', error='rejected by operator', completed_at=now() WHERE id=$1 AND status IN ('approved','pending')`,
				*callID); err != nil {
				return nil, err
			}
		}
	}

	// Run becomes running again with NO lease: claimable through the normal
	// fenced-claim path. completed_at/error stay NULL (it never finished).
	if _, err := tx.Exec(ctx, `UPDATE agent_runs
	    SET status=$2, completed_at=NULL, error='', termination_reason='',
	    lease_owner='', lease_expires_at=NULL
	    WHERE id=$1 AND status='needs_approval'`, runID, model.RunRunning); err != nil {
		return nil, err
	}
	a.Status = decision
	a.DecidedBy = decidedBy
	return &a, tx.Commit(ctx)
}

var ErrApprovalAlreadyDecided = errors.New("approval already decided")
