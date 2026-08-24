package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/durablemcp"
	"github.com/incidentgraph/incidentgraph/internal/evidence"
	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/memory"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/incidentgraph/incidentgraph/internal/testdb"
	"github.com/incidentgraph/incidentgraph/internal/tools"
)

// ---------------------------------------------------------------- harness

func newRunner(t *testing.T, mutate func(*Deps)) (*NativeRunner, *runs.Store) {
	t.Helper()
	pool := testdb.Open(t)
	ctx := context.Background()
	emb := retrieval.NewHashEmbedder(1536)
	ret := retrieval.NewStore(pool, emb)
	mem := memory.NewStore(pool, emb)
	eng := policy.New()
	registry := tools.NewRegistry(
		tools.NewSearchDocs(pool, ret),
		tools.NewSearchLogs(pool, ret),
		tools.NewSearchCode(pool, ret),
		tools.NewGetDeployment(pool, ret),
		tools.NewGetGitDiff(pool, ret),
		tools.NewReadFile(pool, ret),
		tools.NewQueryMetrics(pool, ret),
		tools.NewRestartService(),
	)
	store := runs.NewStore(pool)
	recorder := llm.UsageRecorder(func(rec llm.UsageRecord) {
		_ = store.RecordUsage(ctx, rec.RunID, rec)
	})
	router := llm.NewRouter(llm.NewMock("mock-large"), llm.NewMock("mock-small"), llm.NewMock("mock-small"), recorder, 2)
	deps := Deps{
		Runs: store, Policy: eng, Tools: registry,
		Evidence: evidence.NewStore(pool), Memory: mem, Retrieval: ret,
		LLM: router, Security: security.NewStore(pool), Durable: nil,
		Budgets: Budgets{MaxSteps: 40, MaxToolCalls: 25, MaxSameToolRepeats: 5,
			MaxTokenBudget: 200000, MaxCostCents: 5.0},
		Log: nil,
	}
	if mutate != nil {
		mutate(&deps)
	}
	return NewNative(deps), store
}

func seedCorpus(t *testing.T, deps *Deps) {
	t.Helper()
	ctx := context.Background()
	docs := []struct{ path, typ, body string }{
		{"runbooks/checkout.md", "runbook",
			"# Checkout runbook\n\n## High latency\n\nIf checkout latency rises, inspect the database connection pool.\nA pool exhausted state shows acquire timeouts and elevated db wait."},
		{"deployments/checkout/c9f17a2d.txt", "deployment",
			"deployment service=checkout commit c9f17a2d changed POOL_SIZE from 40 to 5. Pool size regression suspected."},
		{"logs/checkout.log", "log",
			"2026-08-23T10:00:00Z checkout ERROR connection pool exhausted acquire timeout after 5s db wait spiked\n2026-08-23T10:01:00Z checkout WARN pool_size=5 all connections in use"},
		{"metrics/db_wait.json", "metrics",
			`{"series":"db_wait_ms","service":"checkout","points":[["10:00",2100],["10:05",2600]],"note":"db wait increased after deployment; redis latency remained stable"}`},
	}
	for _, d := range docs {
		if _, _, err := deps.Retrieval.Ingest(ctx, retrieval.DocumentInput{
			SourceType: d.typ, Service: "checkout", Path: d.path, Title: d.path,
			TrustLevel: model.TrustInternalDoc, RawContent: d.body,
		}); err != nil {
			t.Fatalf("seed corpus %s: %v", d.path, err)
		}
	}
}

func createIncidentWithRun(t *testing.T, store *runs.Store, description string) (incidentID, runID string) {
	t.Helper()
	ctx := context.Background()
	incidentID = model.New()
	if err := store.CreateIncident(ctx, model.Incident{
		ID: incidentID, Title: "Checkout latency 180ms -> 2.6s after deployment",
		Description: description, Service: "checkout", Severity: "sev2",
	}); err != nil {
		t.Fatalf("create incident: %v", err)
	}
	runID = model.New()
	if err := store.CreateRun(ctx, model.AgentRun{
		ID: runID, IncidentID: incidentID, AgentBackend: "native-v1",
		Status: model.RunRunning,
	}); err != nil {
		t.Fatalf("create run: %v", err)
	}
	return incidentID, runID
}

func waitForStatus(t *testing.T, store *runs.Store, runID string, statuses ...string) *model.AgentRun {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		r, err := store.GetRun(context.Background(), runID)
		if err == nil && r != nil {
			for _, s := range statuses {
				if r.Status == s {
					return r
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("run %s did not reach %v in time", runID[:8], statuses)
	return nil
}

const poolIncidentDescription = "Checkout latency increased from 180ms to 2.6s right after deployment. " +
	"Database connection pool exhausted, db wait spiked. Find the likely root cause and show evidence."

// ---------------------------------------------------------------- happy path

func TestNativeRunCompletesPersistingFullTrace(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) { depsSnapshot = d })
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)
	if err := runner.Start(context.Background(), runID); err != nil {
		t.Fatalf("start: %v", err)
	}
	fin := waitForStatus(t, store, runID, model.RunComplete)

	if fin.TerminationReason != "SUCCESS" {
		t.Fatalf("termination reason = %q (%s), want SUCCESS", fin.TerminationReason, fin.Error)
	}

	steps, _ := store.Steps(context.Background(), runID)
	seen := map[string]bool{}
	for _, s := range steps {
		seen[s.StepType] = true
	}
	for _, phase := range []string{"context_build", "plan", "investigate", "hypothesis", "verify", "synthesize"} {
		if !seen[phase] {
			t.Errorf("missing persisted step for phase %q (steps=%v)", phase, seen)
		}
	}

	hyps, _ := runner.deps.Evidence.Hypotheses(context.Background(), runID)
	if len(hyps) == 0 {
		nodes2, _ := runner.deps.Evidence.Nodes(context.Background(), runID)
		for _, n := range nodes2 {
			t.Logf("node type=%s src=%s content=%.120q", n.Type, n.Source, n.Content)
		}
		t.Fatal("expected persisted hypotheses")
	}
	nodes, _ := runner.deps.Evidence.Nodes(context.Background(), runID)
	if len(nodes) < 3 {
		t.Errorf("expected >=3 evidence nodes, got %d", len(nodes))
	}
	usage, _ := store.ModelUsage(context.Background(), runID)
	if len(usage) == 0 {
		t.Error("expected model_usage rows (usage tracking)")
	}
	if fin.TotalTokens <= 0 {
		t.Errorf("run total_tokens not accumulated: %d", fin.TotalTokens)
	}
	calls, _ := store.ToolCalls(context.Background(), runID)
	if len(calls) < 3 {
		t.Errorf("expected >=3 tool calls, got %d", len(calls))
	}
	events, _ := store.EventsSince(context.Background(), runID, 0)
	if len(events) == 0 {
		t.Error("expected persisted run_events (SSE replay log)")
	}
}

// ---------------------------------------------------------------- durable approval flow

// fakeDurable implements just enough of the DurableMCP wire protocol for the
// agent's durable path: MCP initialize/tools/call plus the REST read API.
type fakeDurable struct {
	srv    *httptest.Server
	client *durablemcp.Client

	mu     sync.Mutex
	seq    int
	execs  map[string]*durablemcp.Execution
	events map[string][]durablemcp.Event
	calls  int
}

func newFakeDurable(t *testing.T) *fakeDurable {
	f := &fakeDurable{execs: map[string]*durablemcp.Execution{}, events: map[string][]durablemcp.Event{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     int64           `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			writeRPC(w, req.ID, map[string]any{"capabilities": map[string]any{}})
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
				Meta      struct {
					IdempotencyKey string `json:"idempotency_key"`
					Namespace      string `json:"namespace"`
				} `json:"_meta"`
			}
			_ = json.Unmarshal(req.Params, &p)
			f.mu.Lock()
			f.calls++
			f.seq++
			id := fmt.Sprintf("exec-%d", f.seq)
			exec := &durablemcp.Execution{
				ID: id, Namespace: p.Meta.Namespace, ToolName: p.Name,
				IdempotencyKey: p.Meta.IdempotencyKey, InputArgs: p.Arguments,
				Status: "completed", Attempts: 1, MaxAttempts: 3,
				Result: json.RawMessage(`{"status":"restarted","service":"checkout"}`),
			}
			f.execs[id] = exec
			f.events[id] = []durablemcp.Event{
				{ID: 1, ExecutionID: id, EventType: "started"},
				{ID: 2, ExecutionID: id, EventType: "completed"},
			}
			f.mu.Unlock()
			writeRPC(w, req.ID, durablemcp.SubmitResult{ExecutionID: id, Status: "queued"})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	})
	mux.HandleFunc("GET /api/v1/executions/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		e := f.execs[r.PathValue("id")]
		f.mu.Unlock()
		if e == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("GET /api/v1/executions/{id}/events", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		ev := f.events[r.PathValue("id")]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"events": ev})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	f.client = durablemcp.New(f.srv.URL, "", 5*time.Second)
	return f
}

func writeRPC(w http.ResponseWriter, id int64, result any) {
	b, _ := json.Marshal(result)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id, "result": json.RawMessage(b),
	})
}

func TestApprovalPauseApproveResumeExecutesDurably(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		d.Durable = newFakeDurable(t).client
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store,
		poolIncidentDescription+" Operator asked us to remediate once root cause is confirmed.")

	// Start asynchronously; expect a pause at NEEDS_APPROVAL.
	done := make(chan error, 1)
	go func() { done <- runner.Start(context.Background(), runID) }()
	fin := waitForStatus(t, store, runID, model.RunNeedsApproval)
	if err := <-done; err != nil {
		t.Fatalf("start returned error: %v", err)
	}
	if fin.Status != model.RunNeedsApproval {
		t.Fatalf("status = %s", fin.Status)
	}

	pa, err := store.PendingApproval(context.Background(), runID)
	if err != nil || pa == nil {
		t.Fatalf("no pending approval: %v", err)
	}
	if pa.Tool != "restart_service" {
		t.Fatalf("approval tool = %s, want restart_service", pa.Tool)
	}
	tc, err := store.GetToolCall(context.Background(), *pa.ToolCallID)
	if err != nil {
		t.Fatalf("tool call load: %v", err)
	}
	if tc.RiskLevel != string(model.RiskWrite) || tc.PolicyDecision != string(model.PolicyNeedsApproval) {
		t.Fatalf("policy did not gate write tool: risk=%s decision=%s", tc.RiskLevel, tc.PolicyDecision)
	}

	// Human approves; resume continues exactly from persisted state.
	if err := store.DecideApproval(context.Background(), pa.ID, "approved", "ops-oncall"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	_ = store.UpdateToolCallPolicy(context.Background(), tc.ID, "allowed", "approved")
	if err := runner.Resume(context.Background(), runID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	fin = waitForStatus(t, store, runID, model.RunComplete)
	if fin.TerminationReason != "SUCCESS" {
		t.Fatalf("termination = %q, want SUCCESS", fin.TerminationReason)
	}

	tc, _ = store.GetToolCall(context.Background(), *pa.ToolCallID)
	if tc.Status != "succeeded" {
		t.Fatalf("approved tool call status = %s (%s), want succeeded", tc.Status, tc.Error)
	}
	if !strings.HasPrefix(tc.DurableExecutionID, "exec-") {
		t.Fatalf("durable execution id not persisted on tool_call: %q", tc.DurableExecutionID)
	}
	if !strings.HasPrefix(tc.ResultReference, "durablemcp:") {
		t.Errorf("result reference should point at DurableMCP execution, got %q", tc.ResultReference)
	}
	timeline, _ := store.ToolCallTimeline(context.Background(), tc.ID)
	kinds := map[string]bool{}
	for _, e := range timeline {
		kinds[e.EventType] = true
	}
	for _, want := range []string{"requested", "submitted", "completed"} {
		if !kinds[want] {
			t.Errorf("tool_call_events missing %q (have %v)", want, kinds)
		}
	}
	apprs, _ := store.ApprovalsForRun(context.Background(), runID)
	if len(apprs) != 1 || apprs[0].DecidedBy != "ops-oncall" {
		t.Errorf("approval record incorrect: %+v", apprs)
	}
}

func TestApprovalRejectDeniesExecution(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		d.Durable = newFakeDurable(t).client
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store,
		poolIncidentDescription+" Operator asked us to remediate once root cause is confirmed.")

	done := make(chan error, 1)
	go func() { done <- runner.Start(context.Background(), runID) }()
	waitForStatus(t, store, runID, model.RunNeedsApproval)
	if err := <-done; err != nil {
		t.Fatalf("start error: %v", err)
	}

	pa, _ := store.PendingApproval(context.Background(), runID)
	if err := store.DecideApproval(context.Background(), pa.ID, "rejected", "ops-oncall"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if err := runner.Resume(context.Background(), runID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	waitForStatus(t, store, runID, model.RunComplete)

	tc, _ := store.GetToolCall(context.Background(), *pa.ToolCallID)
	if tc.Status != "denied" {
		t.Fatalf("rejected tool call status = %s, want denied", tc.Status)
	}
	if tc.DurableExecutionID != "" {
		t.Errorf("rejected call must never execute durably, got %q", tc.DurableExecutionID)
	}
}

func TestDegradedWhenDurableUnavailable(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		d.Durable = nil // DurableMCP not configured at all
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
	_ = store.DecideApproval(context.Background(), pa.ID, "approved", "ops-oncall")
	_ = store.UpdateToolCallPolicy(context.Background(), *pa.ToolCallID, "allowed", "approved")
	if err := runner.Resume(context.Background(), runID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	waitForStatus(t, store, runID, model.RunComplete)

	tc, _ := store.GetToolCall(context.Background(), *pa.ToolCallID)
	if tc.Status != "degraded" {
		t.Fatalf("status = %s, want explicit degraded (never silently local)", tc.Status)
	}
	if tc.Error == "" || !strings.Contains(tc.Error, "DurableMCP unavailable") {
		t.Errorf("degraded reason missing: %q", tc.Error)
	}
}

// ---------------------------------------------------------------- cancellation & budgets

// slowProvider delays every generation so cancel can race the drive loop.
type slowProvider struct{ delay time.Duration }

func (p *slowProvider) Name() string { return "slow-mock" }
func (p *slowProvider) Generate(ctx context.Context, req llm.GenRequest) (*llm.GenResponse, error) {
	select {
	case <-time.After(p.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return llm.NewMock("mock-large").Generate(ctx, req)
}

func TestCancelMidFlightIsFinal(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		slow := &slowProvider{delay: 400 * time.Millisecond}
		d.LLM = llm.NewRouter(slow, slow, slow, nil, 1)
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)

	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)
	go func() { _ = runner.Start(context.Background(), runID) }()

	time.Sleep(80 * time.Millisecond) // let it enter plan/context_build
	if err := runner.Cancel(context.Background(), runID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForStatus(t, store, runID, model.RunCancelled)

	r, err := store.GetRun(context.Background(), runID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if r.Status != model.RunCancelled {
		t.Fatalf("cancelled run was overwritten to %s by in-flight driver", r.Status)
	}
	if r.TerminationReason != "CANCELLED" {
		t.Errorf("termination_reason = %q", r.TerminationReason)
	}
}

func TestTokenBudgetTerminatesRun(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		d.Budgets.MaxTokenBudget = 50 // absurdly small: first budget check fails
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)

	// Pre-record usage so the refreshed totals trip MAX_TOKENS immediately.
	_ = store.RecordUsage(context.Background(), runID, llm.UsageRecord{
		RunID: runID, Provider: "mock", Model: "mock-large",
		InputTokens: 100, OutputTokens: 20,
	})

	if err := runner.Start(context.Background(), runID); err != nil {
		t.Fatalf("start: %v", err)
	}
	fin := waitForStatus(t, store, runID, model.RunFailed)
	if fin.TerminationReason != "MAX_TOKENS" {
		t.Fatalf("termination_reason = %q, want MAX_TOKENS", fin.TerminationReason)
	}
}

func TestMaxSameToolRepeatsGuardsLoop(t *testing.T) {
	var depsSnapshot *Deps
	runner, store := newRunner(t, func(d *Deps) {
		d.Budgets.MaxSameToolRepeats = 0 // no repeats allowed at all
		depsSnapshot = d
	})
	seedCorpus(t, depsSnapshot)
	_, runID := createIncidentWithRun(t, store, poolIncidentDescription)

	if err := runner.Start(context.Background(), runID); err != nil {
		t.Fatalf("start: %v", err)
	}
	fin := waitForStatus(t, store, runID, model.RunFailed)
	if fin.TerminationReason != "TOOL_LOOP" {
		t.Fatalf("termination_reason = %q, want TOOL_LOOP", fin.TerminationReason)
	}
}
