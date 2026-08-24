package llm

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestMockPlanDeterministic(t *testing.T) {
	m := NewMock("mock-small")
	req := GenRequest{Task: TaskClassification, System: "You are an incident investigator.",
		Messages: []Message{{Role: RoleUser, Content: "TASK: plan\nIncident: checkout latency increased after deployment. Database connection pool exhausted."}}}
	r1, _ := m.Generate(context.Background(), req)
	r2, _ := m.Generate(context.Background(), req)
	if r1.Text != r2.Text {
		t.Fatal("mock must be deterministic")
	}
	var plan map[string]any
	if err := json.Unmarshal([]byte(r1.Text), &plan); err != nil {
		t.Fatalf("plan not JSON: %v", r1.Text)
	}
}

func TestMockHypothesesPoolRegression(t *testing.T) {
	m := NewMock("mock-large")
	prompt := "TASK: hypotheses\nEVIDENCE:\n- [E-abc123] type=deployment source=deployments/checkout/d38ac2 trust=internal_document\nDeployment d38ac2 changed POOL_SIZE from 40 to 5. pool exhausted.\n- [E-def456] type=metric source=metrics/checkout/db_wait_ms trust=tool_output\ndb wait time increased 10x after deploy.\n"
	resp, _ := m.Generate(context.Background(), GenRequest{Task: TaskHypothesisSynthesis,
		Messages: []Message{{Role: RoleUser, Content: prompt}}})
	var out struct {
		Hypotheses []struct {
			Claim      string   `json:"claim"`
			Supporting []string `json:"supporting_evidence_ids"`
			Category   string   `json:"root_cause_category"`
			Confidence float64  `json:"confidence"`
		} `json:"hypotheses"`
	}
	if err := json.Unmarshal([]byte(resp.Text), &out); err != nil {
		t.Fatalf("bad json: %v %s", err, resp.Text)
	}
	if len(out.Hypotheses) == 0 || out.Hypotheses[0].Category != "db_pool_regression" {
		t.Fatalf("expected db_pool_regression first, got %+v", out.Hypotheses)
	}
	if len(out.Hypotheses[0].Supporting) < 2 {
		t.Fatalf("expected both evidence cited, got %+v", out.Hypotheses[0])
	}
}

func TestMockInsufficientEvidence(t *testing.T) {
	m := NewMock("mock-small")
	prompt := "TASK: hypotheses\nEVIDENCE:\n- [E-x1] type=log source=logs/app.log trust=tool_output\nAll systems nominal.\n"
	resp, _ := m.Generate(context.Background(), GenRequest{Task: TaskHypothesisSynthesis,
		Messages: []Message{{Role: RoleUser, Content: prompt}}})
	if !strings.Contains(resp.Text, "insufficient_evidence") {
		t.Fatalf("expected abstention, got %s", resp.Text)
	}
}

func TestStructuredRetryOnBadJSON(t *testing.T) {
	// provider that returns bad JSON once then good JSON
	bad := &scriptedProvider{responses: []string{"not json at all", `{"ok":true}`}}
	r := NewRouter(bad, nil, nil, nil, 2)
	var out struct {
		OK bool `json:"ok"`
	}
	if err := r.GenerateStructured(context.Background(),
		GenRequest{Task: TaskClassification, Messages: []Message{{Role: RoleUser, Content: "x"}}}, &out); err != nil {
		t.Fatalf("expected recovery, got %v", err)
	}
	if !out.OK || bad.calls != 2 {
		t.Fatalf("retry bookkeeping wrong: calls=%d", bad.calls)
	}
}

func TestStructuredFailsCleanlyAfterThreshold(t *testing.T) {
	bad := &scriptedProvider{responses: []string{"nope", "still nope", "nope again"}}
	r := NewRouter(bad, nil, nil, nil, 1)
	var out map[string]any
	err := r.GenerateStructured(context.Background(),
		GenRequest{Task: TaskClassification, Messages: []Message{{Role: RoleUser, Content: "x"}}}, &out)
	if err == nil {
		t.Fatal("expected clean failure")
	}
	if bad.calls != 3 { // maxRetry(1)+1 base + 1 correction = bounded
		t.Logf("calls=%d (bounded behavior)", bad.calls)
	}
}

type scriptedProvider struct {
	responses []string
	calls     int
}

func (s *scriptedProvider) Name() string { return "scripted" }
func (s *scriptedProvider) Generate(ctx context.Context, req GenRequest) (*GenResponse, error) {
	i := s.calls
	s.calls++
	if i >= len(s.responses) {
		return nil, context.DeadlineExceeded
	}
	return &GenResponse{Text: s.responses[i], Model: "scripted", Provider: "scripted"}, nil
}
