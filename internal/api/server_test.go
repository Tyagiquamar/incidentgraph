package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/auth"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/openclaw"
	"github.com/incidentgraph/incidentgraph/internal/testdb"
)

// stubRunner records lifecycle calls without driving anything.
type stubRunner struct {
	mu        sync.Mutex
	started   []string
	resumed   []string
	cancelled []string
}

func (f *stubRunner) Start(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, id)
	return nil
}
func (f *stubRunner) Resume(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumed = append(f.resumed, id)
	return nil
}
func (f *stubRunner) Cancel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id)
	return nil
}

// snapshot returns copies safe for concurrent reads.
func (f *stubRunner) snapshot() (started, resumed, cancelled []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.started...), append([]string{}, f.resumed...), append([]string{}, f.cancelled...)
}

func newTestServer(t *testing.T, mutate func(*ServerConfig)) (*Server, *stubRunner) {
	t.Helper()
	pool := testdb.Open(t)
	runner := &stubRunner{}
	cfg := ServerConfig{
		Auth: auth.Config{Enabled: true,
			AdminToken: "t-admin", OperatorToken: "t-op", ViewerToken: "t-view"},
	}
	s := NewServer(cfg, pool, nil, nil, nil, nil)
	s.runner = runner
	if mutate != nil {
		mutate(&cfg)
	}
	return s, runner
}

func doReq(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHermesBackendRejectedWhenUnconfigured(t *testing.T) {
	s, _ := newTestServer(t, nil)
	ctx := context.Background()
	inc := model.Incident{ID: model.New(), Title: "t-" + model.New()[:8], Service: "checkout", Severity: "sev2"}
	_ = s.runs.CreateIncident(ctx, inc)

	rec := doReq(t, s.Handler(), "POST", "/incidents/"+inc.ID+"/runs", "t-op",
		map[string]string{"backend": "hermes"})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s, want 503 (honest refusal)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not configured") {
		t.Errorf("body should explain misconfiguration: %s", rec.Body.String())
	}
}

func TestRoleEnforcementOnWriteRoutes(t *testing.T) {
	s, _ := newTestServer(t, nil)
	h := s.Handler()

	if rec := doReq(t, h, "POST", "/incidents", "", map[string]string{"title": "x", "service": "y"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous create = %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/incidents", "t-view", map[string]string{"title": "x", "service": "y"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("viewer create = %d, want 401", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/incidents", "t-op", map[string]string{"title": "x", "service": "y"}); rec.Code != http.StatusCreated {
		t.Fatalf("operator create = %d (%s), want 201", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, h, "GET", "/incidents", "t-view", nil); rec.Code != http.StatusOK {
		t.Fatalf("viewer list = %d, want 200", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/evals/run", "t-op", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("operator eval-run = %d, want 401 (admin only)", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/evals/run", "t-admin", nil); rec.Code == http.StatusUnauthorized {
		t.Fatalf("admin eval-run unauthorized")
	}
}

func TestApprovalDecisionAttributesPrincipal(t *testing.T) {
	s, runner := newTestServer(t, nil)
	ctx := context.Background()

	inc := model.Incident{ID: model.New(), Title: "t-" + model.New()[:8], Service: "checkout"}
	_ = s.runs.CreateIncident(ctx, inc)
	runID := model.New()
	_ = s.runs.CreateRun(ctx, model.AgentRun{ID: runID, IncidentID: inc.ID, Status: model.RunNeedsApproval})
	callID := model.New()
	_ = s.runs.CreateToolCall(ctx, model.ToolCall{
		ID: callID, RunID: runID, ToolName: "restart_service",
		Arguments: json.RawMessage(`{"service":"checkout"}`),
		RiskLevel: "write", PolicyDecision: "needs_approval",
	})
	apprID, err := s.runs.CreateApproval(ctx, model.Approval{
		RunID: runID, ToolCallID: &callID, Tool: "restart_service", Risk: "write"})
	if err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, s.Handler(), "POST", "/approvals/"+apprID+"/approve", "t-op", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve = %d (%s)", rec.Code, rec.Body.String())
	}
	appr, _ := s.runs.GetApproval(ctx, apprID)
	if appr.DecidedBy != "operator" {
		t.Fatalf("decided_by = %q, want authenticated principal name", appr.DecidedBy)
	}
	// resume is async; wait briefly for the stub to observe it
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, resumed, _ := runner.snapshot()
		if len(resumed) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	started, resumed, _ := runner.snapshot()
	if len(resumed) != 1 || resumed[0] != runID {
		t.Fatalf("resume not triggered for paused run: %v", resumed)
	}
	_ = started
	tc, _ := s.runs.GetToolCall(ctx, callID)
	if tc.Status != "approved" && tc.PolicyDecision != "allowed" {
		t.Fatalf("tool call not marked approved: %+v", tc)
	}
}

func TestOpenClawWebhookInvestigateAndApprove(t *testing.T) {
	s, runner := newTestServer(t, nil)
	gw := openclaw.NewGateway()
	gw.RegisterPrincipal(openclaw.Principal{
		Channel: "slack", Workspace: "acme", UserID: "u1", Role: "operator"})
	s.SetOpenClaw(gw, "secret-token")

	postWebhook := func(payload map[string]any, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/openclaw/webhook", bytes.NewReader(mustJSON(payload)))
		if tok != "" {
			req.Header.Set("X-Verify-Token", tok)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	if rec := postWebhook(map[string]any{"channel": "slack", "user_id": "u1", "text": "/incident investigate checkout latency"}, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("webhook without token = %d, want 401", rec.Code)
	}
	rec := postWebhook(map[string]any{"channel": "slack", "workspace": "acme", "user_id": "u1",
		"text": "/incident investigate Checkout latency increased after deployment"}, "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook = %d (%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		Reply      string `json:"reply"`
		RunID      string `json:"run_id"`
		IncidentID string `json:"incident_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.RunID == "" || !strings.Contains(out.Reply, "started") {
		t.Fatalf("unexpected webhook response: %s", rec.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		started, _, _ := runner.snapshot()
		if len(started) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	started, _, _ := runner.snapshot()
	if len(started) != 1 || started[0] != out.RunID {
		t.Fatalf("run not started via ingress: %v vs %s", started, out.RunID)
	}

	// unregistered user gets rejected politely
	rec = postWebhook(map[string]any{"channel": "slack", "workspace": "acme", "user_id": "intruder",
		"text": "/incident investigate hack"}, "secret-token")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "not registered") {
		t.Fatalf("unregistered principal handling wrong: %d %s", rec.Code, rec.Body.String())
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
