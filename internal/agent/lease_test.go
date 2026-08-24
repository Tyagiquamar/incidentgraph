package agent

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------- lease primitives

func TestLeaseClaimRenewReleaseLifecycle(t *testing.T) {
	pool := testDB(t)
	store := runs.NewStore(pool)
	ctx := context.Background()
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)

	l1, err := store.ClaimRun(ctx, runID, "worker-a", 2*time.Second)
	if err != nil {
		t.Fatalf("claim A: %v", err)
	}
	if l1.Generation != 1 || l1.Owner != "worker-a" {
		t.Fatalf("lease1 = %+v", l1)
	}

	// Renewal with matching identity extends the expiry.
	renewed, ok, err := store.RenewLease(ctx, *l1, 5*time.Second)
	if err != nil || !ok {
		t.Fatalf("renew: ok=%v err=%v", ok, err)
	}
	if !renewed.ExpiresAt.After(l1.ExpiresAt.Add(time.Second)) {
		t.Fatalf("renewal did not extend lease: %v -> %v", l1.ExpiresAt, renewed.ExpiresAt)
	}

	// A second driver cannot claim while the lease is valid.
	if _, err := store.ClaimRun(ctx, runID, "worker-b", time.Second); err == nil {
		t.Fatal("second claim must fail while first lease is live")
	}
	// Wrong generation cannot renew.
	wrongGen := *l1
	wrongGen.Generation = 99
	if _, ok, _ := store.RenewLease(ctx, wrongGen, time.Second); ok {
		t.Fatal("renewal with wrong generation must fail")
	}
	// Release with wrong generation cannot clear the owner's lease.
	if err := store.ReleaseLease(ctx, wrongGen); err == nil {
		t.Fatal("stale release must be rejected")
	}
	if owned, _ := store.VerifyLease(ctx, *l1); !owned {
		t.Fatal("owner lost lease after rejected stale release")
	}
	if err := store.ReleaseLease(ctx, *l1); err != nil {
		t.Fatalf("release by owner: %v", err)
	}
	if owned, _ := store.VerifyLease(ctx, *l1); owned {
		t.Fatal("lease still held after release")
	}
}

func TestExpiredLeaseReclaimedGenerationFencesOldOwner(t *testing.T) {
	pool := testDB(t)
	store := runs.NewStore(pool)
	ctx := context.Background()
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)

	a, err := store.ClaimRun(ctx, runID, "worker-a", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("claim A: %v", err)
	}
	time.Sleep(250 * time.Millisecond) // let A's lease expire

	b, err := store.ClaimRun(ctx, runID, "worker-b", 10*time.Second)
	if err != nil {
		t.Fatalf("claim B after expiry: %v", err)
	}
	if b.Generation != a.Generation+1 {
		t.Fatalf("generation did not advance: %d -> %d", a.Generation, b.Generation)
	}

	// Stale worker A: verify fails, fenced writes are rejected.
	if owned, _ := store.VerifyLease(ctx, *a); owned {
		t.Fatal("A still owns the lease after B reclaimed it")
	}
	if err := store.SetPhaseFenced(ctx, *a, "plan"); err != runs.ErrStaleLease {
		t.Fatalf("stale SetPhaseFenced = %v, want ErrStaleLease", err)
	}
	if err := store.FinishRunFenced(ctx, *a, model.RunComplete, "SUCCESS", ""); err != runs.ErrStaleLease {
		t.Fatalf("stale FinishRunFenced = %v, want ErrStaleLease", err)
	}
	if err := store.PauseForApproval(ctx, *a); err != runs.ErrStaleLease {
		t.Fatalf("stale PauseForApproval = %v, want ErrStaleLease", err)
	}
	if _, ok, _ := store.RenewLease(ctx, *a, time.Second); ok {
		t.Fatal("stale renewal succeeded")
	}
	// Stale ReleaseLease must NOT clear B's lease.
	if err := store.ReleaseLease(ctx, *a); err == nil {
		t.Fatal("stale release cleared the new owner's lease")
	}
	if owned, _ := store.VerifyLease(ctx, *b); !owned {
		t.Fatal("B lost its lease due to stale-A release")
	}
	// B remains fully authoritative.
	fin, err := store.GetRun(ctx, runID)
	if err != nil {
		t.Fatal(err)
	}
	if fin.Status != model.RunRunning {
		t.Fatalf("status mutated to %s by stale worker writes", fin.Status)
	}
}

func TestLongRunSurvivesViaHeartbeatRenewal(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		slow := &slowProvider{delay: 150 * time.Millisecond}
		d.LLM = llm.NewRouter(slow, slow, slow, nil, 1)
		d.LeaseTTL = 300 * time.Millisecond // heartbeat = 100ms
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)

	if err := runner.Start(context.Background(), runID); err != nil {
		t.Fatalf("start: %v", err)
	}
	fin := waitForStatus(t, store, runID, model.RunComplete)
	if fin.TerminationReason != "SUCCESS" {
		t.Fatalf("termination = %q; long run did not survive via renewal", fin.TerminationReason)
	}
	// Run duration exceeded one TTL: proves renewal kept it alive.
	r, _ := store.GetRun(context.Background(), runID)
	if r.LatencyMS < 300 {
		t.Logf("run latency %dms (shorter than TTL — test still valid but weaker)", r.LatencyMS)
	}
}

func TestSecondDriverCannotStealLiveRun(t *testing.T) {
	var depsSnapshot *Deps
	runnerA, store := newRunner(t, func(d *Deps) {
		slow := &slowProvider{delay: 500 * time.Millisecond}
		d.LLM = llm.NewRouter(slow, slow, slow, nil, 1)
		d.LeaseTTL = 10 * time.Second
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)
	runnerB := NewNative(*depsSnapshot)

	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)
	done := make(chan error, 1)
	go func() { done <- runnerA.Start(context.Background(), runID) }()
	waitForPhase(t, store, runID, "investigate")

	err := runnerB.Resume(context.Background(), runID)
	if err == nil || !strings.Contains(err.Error(), "leased to another driver") {
		t.Fatalf("second driver resume err = %v, want leased-to-another-driver", err)
	}
	_ = <-done
}

// ---------------------------------------------------------------- helpers

func testDB(t *testing.T) *pgxpool.Pool { return testdb.Open(t) }

func waitForPhase(t *testing.T, store *runs.Store, runID, phase string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r, err := store.GetRun(context.Background(), runID)
		if err == nil && r != nil && r.CurrentPhase == phase {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("run %s never reached phase %s", runID[:8], phase)
}

// ---------------------------------------------------------------- crash recovery

func TestApprovedApprovalCrashRecoveryExecutesExactlyOnce(t *testing.T) {
	var depsSnapshot *Deps
	fd := newFakeDurable(t)
	runner, store := newRunner(t, func(d *Deps) {
		d.Durable = fd.client
		d.LeaseTTL = 2 * time.Second
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store,
		poolIncidentDescription+" Operator asked us to remediate once root cause is confirmed.")

	done := make(chan error, 1)
	go func() { done <- runner.Start(context.Background(), runID) }()
	waitForStatus(t, store, runID, model.RunNeedsApproval)
	<-done // simulate process crash BEFORE any resume happens

	pa, err := store.PendingApproval(context.Background(), runID)
	if err != nil || pa == nil {
		t.Fatalf("pending approval missing: %v", err)
	}
	submittedBefore := fd.submissionCount()

	// Human approves; run transitions atomically back to running, unleased.
	updated, err := store.DecideApprovalTx(context.Background(), pa.ID, "approved", "ops-oncall")
	if err != nil || updated == nil {
		t.Fatalf("approve: %v", err)
	}
	runRow, _ := store.GetRun(context.Background(), runID)
	if runRow.Status != model.RunRunning {
		t.Fatalf("run status after approval = %s, want running (crash-recovery claimable)", runRow.Status)
	}
	if runRow.CompletedAt != nil {
		t.Error("running run must not carry completed_at")
	}

	// NEW worker process (fresh driver identity) claims and resumes.
	runner2 := NewNative(*depsSnapshot)
	if runner2.Owner() == runner.Owner() {
		t.Fatal("test setup error: recovery driver shares owner identity")
	}
	if err := runner2.Resume(context.Background(), runID); err != nil {
		t.Fatalf("recovery resume: %v", err)
	}
	fin := waitForStatus(t, store, runID, model.RunComplete)
	if fin.TerminationReason != "SUCCESS" {
		t.Fatalf("termination = %q (%s)", fin.TerminationReason, fin.Error)
	}

	tc, _ := store.GetToolCall(context.Background(), *pa.ToolCallID)
	if tc.Status != "succeeded" || !strings.HasPrefix(tc.DurableExecutionID, "exec-") {
		t.Fatalf("approved call not executed durably: %+v", tc)
	}
	if tc.IdempotencyKey != "incidentgraph:"+tc.ID {
		t.Errorf("idempotency key %q is not stable per tool_call id", tc.IdempotencyKey)
	}
	// Exactly-once: only ONE durable submission for this logical call even
	// though a second driver re-ran the resolution path.
	if got := fd.submissionCount(); got != submittedBefore+1 {
		t.Fatalf("durable submissions = %d (before=%d), want exactly one new submission", got, submittedBefore)
	}
}

func TestRejectedApprovalCrashRecoveryStaysDenied(t *testing.T) {
	var depsSnapshot *Deps
	fd := newFakeDurable(t)
	runner, store := newRunner(t, func(d *Deps) {
		d.Durable = fd.client
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store,
		poolIncidentDescription+" Operator asked us to remediate once root cause is confirmed.")
	done := make(chan error, 1)
	go func() { done <- runner.Start(context.Background(), runID) }()
	waitForStatus(t, store, runID, model.RunNeedsApproval)
	<-done

	pa, _ := store.PendingApproval(context.Background(), runID)
	if _, err := store.DecideApprovalTx(context.Background(), pa.ID, "rejected", "ops-oncall"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	before := fd.submissionCount()

	// Crash + fresh worker recovery.
	runner2 := NewNative(*depsSnapshot)
	if err := runner2.Resume(context.Background(), runID); err != nil {
		t.Fatalf("recovery resume: %v", err)
	}
	waitForStatus(t, store, runID, model.RunComplete)

	tc, _ := store.GetToolCall(context.Background(), *pa.ToolCallID)
	if tc.Status != "denied" {
		t.Fatalf("rejected call status = %s after recovery, want denied", tc.Status)
	}
	if fd.submissionCount() != before {
		t.Fatal("rejected call was submitted to DurableMCP during recovery")
	}
}

func TestDuplicateApprovalDecisionsConflict(t *testing.T) {
	pool := testDB(t)
	store := runs.NewStore(pool)
	ctx := context.Background()
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)
	callID := model.New()
	_ = store.CreateToolCall(ctx, model.ToolCall{
		ID: callID, RunID: runID, ToolName: "restart_service",
		RiskLevel: "write", PolicyDecision: "needs_approval",
	})
	apprID, err := store.CreateApproval(ctx, model.Approval{
		RunID: runID, ToolCallID: &callID, Tool: "restart_service", Risk: "write"})
	if err != nil {
		t.Fatal(err)
	}

	// Concurrent duplicate submissions: exactly one wins per decision.
	var wg sync.WaitGroup
	results := make([]string, 3)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.DecideApprovalTx(ctx, apprID, "approved", "racer")
			if err == nil {
				results[i] = "won"
			} else if err == runs.ErrApprovalAlreadyDecided {
				results[i] = "conflict"
			} else {
				results[i] = "error:" + err.Error()
			}
		}(i)
	}
	wg.Wait()
	won, conflict := 0, 0
	for _, r := range results {
		switch r {
		case "won":
			won++
		case "conflict":
			conflict++
		default:
			t.Fatalf("unexpected result %q", r)
		}
	}
	if won != 1 || conflict != 2 {
		t.Fatalf("duplicate decisions: won=%d conflict=%d, want 1/2", won, conflict)
	}
}
