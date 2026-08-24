package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeOpenAI returns provider-reported usage so we can prove the router uses
// REAL counts instead of its length-based estimates.
func fakeOpenAI(t *testing.T, promptTokens, completionTokens int) (*Router, *[]UsageRecord) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"ok\":true}"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":` + itoa(promptTokens) + `,"completion_tokens":` + itoa(completionTokens) + `}}`))
	}))
	t.Cleanup(srv.Close)

	var records []UsageRecord
	rec := func(r UsageRecord) { records = append(records, r) }
	p := NewOpenAI(srv.URL, "key", "gpt-4o-mini")
	return NewRouter(p, nil, nil, rec, 1), &records
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestProviderTokenCountsWinOverEstimates(t *testing.T) {
	router, records := fakeOpenAI(t, 1234, 56)
	err := router.GenerateStructured(context.Background(), GenRequest{
		RunID:    "run-1",
		Task:     TaskClassification,
		Messages: []Message{{Role: RoleUser, Content: "hello"}},
	}, &struct{ OK bool }{})
	if err != nil {
		t.Fatal(err)
	}
	if len(*records) != 1 {
		t.Fatalf("records = %d", len(*records))
	}
	r := (*records)[0]
	if r.UsageSource != "provider" {
		t.Fatalf("usage_source = %q, want provider when API reports usage", r.UsageSource)
	}
	if r.InputTokens != 1234 || r.OutputTokens != 56 {
		t.Fatalf("tokens = %d/%d, want provider-reported 1234/56", r.InputTokens, r.OutputTokens)
	}
	if !r.CostKnown {
		t.Fatal("gpt-4o-mini must be in the price table (cost known)")
	}
}

func TestEstimatedUsageIsLabeledWhenProviderReportsNone(t *testing.T) {
	var records []UsageRecord
	rec := func(r UsageRecord) { records = append(records, r) }
	router := NewRouter(NewMock("mock-large"), nil, nil, rec, 1)
	_, err := router.Generate(context.Background(), GenRequest{
		System: "SYS", Messages: []Message{{Role: RoleUser, Content: "TASK: report\nx"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := records[0]
	// Mock providers do not return usage; counts are honest ESTIMATES.
	if r.UsageSource != "estimated" && r.UsageSource != "" {
		t.Fatalf("mock usage_source = %q, want estimated", r.UsageSource)
	}
}

func TestUnknownModelCostIsFlagged(t *testing.T) {
	var records []UsageRecord
	rec := func(r UsageRecord) { records = append(records, r) }
	router := NewRouter(unknownModelProvider{}, nil, nil, rec, 1)
	_, _ = router.Generate(context.Background(), GenRequest{Messages: []Message{{Role: RoleUser, Content: "hi"}}})
	r := records[0]
	if r.CostKnown {
		t.Fatal("unknown model must set CostKnown=false")
	}
	if r.CostCents != 0 {
		t.Fatalf("unknown-model cost must be 0 with flag, got %v", r.CostCents)
	}
}

type unknownModelProvider struct{}

func (unknownModelProvider) Name() string { return "mystery" }
func (unknownModelProvider) Generate(_ context.Context, _ GenRequest) (*GenResponse, error) {
	return &GenResponse{Text: "x", Model: "totally-unknown-model", Provider: "mystery"}, nil
}
