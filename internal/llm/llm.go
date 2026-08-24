// Package llm defines model providers, structured-output generation with
// bounded correction retries, and the task-based model router.
package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

type Message struct {
	Role    Role   `json:"role"`
	Content string `json:"content"`
}

// TaskType drives routing decisions.
type TaskType string

const (
	TaskClassification      TaskType = "classification"
	TaskQueryExpansion      TaskType = "query_expansion"
	TaskHypothesisSynthesis TaskType = "hypothesis_synthesis"
	TaskJudge               TaskType = "judge"
)

// GenRequest is one completion request.
type GenRequest struct {
	RunID       string // associates usage records with an agent run
	Task        TaskType
	System      string
	Messages    []Message
	Temperature float64
	MaxTokens   int
	// Structured: when non-nil, provider must return JSON conforming to hint.
	Structured bool
	SchemaHint string // human-readable schema description for prompting
}

// GenResponse is one completion result.
type GenResponse struct {
	Text         string
	InputTokens  int
	OutputTokens int
	LatencyMS    int64
	Model        string
	Provider     string
	FinishReason string
	Retries      int
	// UsageIsEstimate marks providers whose token counts are self-estimated
	// (e.g. the deterministic mock) rather than measured by a real API.
	UsageIsEstimate bool
}

// Provider is a model backend.
type Provider interface {
	Name() string
	Generate(ctx context.Context, req GenRequest) (*GenResponse, error)
}

// UsageRecorder receives every model invocation for persistence.
type UsageRecorder func(rec UsageRecord)

type UsageRecord struct {
	RunID        string
	EvalRunID    string
	Provider     string
	Model        string
	TaskType     TaskType
	InputTokens  int
	OutputTokens int
	// UsageSource records whether the counts came from the PROVIDER response
	// ("provider", authoritative) or were ESTIMATED from text length
	// ("estimated"). Estimates are honest approximations, never presented as
	// measured usage.
	UsageSource string
	LatencyMS   int64
	CostCents   float64
	// CostKnown is false when the model is absent from the price table: cost
	// stays 0 but is explicitly flagged as unknown rather than "free".
	CostKnown  bool
	Status     string // ok|error|timeout
	RetryCount int
	Error      string
}

// KnownModel reports whether built-in pricing covers this model. Built-in
// prices are ESTIMATES documented in llm.go; unknown models are surfaced so
// dashboards never show fabricated $0 as real cost.
func KnownModel(model string) bool {
	_, ok := priceTable[model]
	return ok
}

// ---------------------------------------------------------------- pricing

type Price struct {
	InputPerMTokCents  float64
	OutputPerMTokCents float64
}

var priceTable = map[string]Price{
	"gpt-4o":      {InputPerMTokCents: 250, OutputPerMTokCents: 1000}, // $2.50/$10 per M
	"gpt-4o-mini": {InputPerMTokCents: 1.5, OutputPerMTokCents: 6},
	"mock-small":  {0.01, 0.03},
	"mock-large":  {0.02, 0.06},
}

func EstimateCost(model string, in, out int) float64 {
	p, ok := priceTable[model]
	if !ok {
		return 0
	}
	return float64(in)/1e6*p.InputPerMTokCents + float64(out)/1e6*p.OutputPerMTokCents
}

// estimateTokens approximates token counts (~4 chars/token).
func estimateTokens(s string) int { return len(s) / 4 }

// ---------------------------------------------------------------- router

// Router picks provider+model per task with primary/fallback and records usage.
type Router struct {
	primary  Provider
	fallback Provider
	judge    Provider
	rec      UsageRecorder
	maxRetry int
}

func NewRouter(primary, fallback, judge Provider, rec UsageRecorder, maxStructuredRetry int) *Router {
	if maxStructuredRetry <= 0 {
		maxStructuredRetry = 2
	}
	if rec == nil {
		rec = func(UsageRecord) {}
	}
	return &Router{primary: primary, fallback: fallback, judge: judge, rec: rec, maxRetry: maxStructuredRetry}
}

func pick(r *Router, t TaskType) Provider {
	switch t {
	case TaskJudge:
		if r.judge != nil {
			return r.judge
		}
		return r.primary
	default:
		return r.primary
	}
}

// Primary exposes the primary provider (used by the judge availability check).
func (r *Router) Primary() Provider { return r.primary }

// Generate runs one completion with failover to the fallback provider.
func (r *Router) Generate(ctx context.Context, req GenRequest) (*GenResponse, error) {
	p := pick(r, req.Task)
	resp, err := p.Generate(ctx, req)
	errStr := ""
	if err != nil {
		errStr = err.Error()
		if r.fallback != nil && r.fallback.Name() != p.Name() {
			resp2, err2 := r.fallback.Generate(ctx, req)
			r.rec(UsageRecord{RunID: req.RunID, Provider: p.Name(), Model: modelOf(req), TaskType: req.Task,
				Status: "error", Error: errStr})
			if err2 == nil {
				resp2.Retries++
				r.record(resp2, req, "")
				return resp2, nil
			}
			return nil, fmt.Errorf("primary(%s): %v; fallback(%s): %v", p.Name(), err, r.fallback.Name(), err2)
		}
	}
	if resp != nil {
		resp.Provider = p.Name()
	}
	r.record(resp, req, errStr)
	return resp, err
}

func modelOf(req GenRequest) string {
	switch req.Task {
	case TaskHypothesisSynthesis:
		return "strong"
	case TaskJudge:
		return "judge"
	default:
		return "cheap"
	}
}

func (r *Router) record(resp *GenResponse, req GenRequest, errStr string) {
	model := ""
	provider := ""
	out := 0
	in := 0
	usageSource := "estimated"
	if resp != nil {
		out = resp.OutputTokens
		model = resp.Model
		provider = resp.Provider
		if resp.InputTokens > 0 || resp.OutputTokens > 0 {
			// Provider-reported usage wins over any estimate.
			in = resp.InputTokens
			usageSource = "provider"
			if resp.UsageIsEstimate {
				usageSource = "estimated"
			}
		} else {
			in = estimateTokens(req.System + concatMessages(req.Messages))
		}
	} else {
		in = estimateTokens(req.System + concatMessages(req.Messages))
		model = modelOf(req)
	}
	cost := EstimateCost(model, in, out)
	r.rec(UsageRecord{
		RunID:    req.RunID,
		Provider: providerName(provider, r), Model: model, TaskType: req.Task,
		InputTokens: in, OutputTokens: out,
		UsageSource: usageSource,
		CostCents:   cost, CostKnown: KnownModel(model),
		Status: statusFor(errStr), RetryCount: retryOf(resp), Error: errStr,
	})
}

func providerName(name string, r *Router) string {
	if name != "" {
		return name
	}
	if r.primary != nil {
		return r.primary.Name()
	}
	return "unknown"
}

func statusFor(err string) string {
	if err == "" {
		return "ok"
	}
	return "error"
}

func retryOf(resp *GenResponse) int {
	if resp == nil {
		return 0
	}
	return resp.Retries
}

func concatMessages(msgs []Message) string {
	s := ""
	for _, m := range msgs {
		s += m.Content
	}
	return s
}

// GenerateStructured decodes JSON output into `out` with bounded correction
// retries: malformed output triggers one repair attempt that includes the
// parse error, up to Router.maxRetry total attempts, then fails cleanly.
func (r *Router) GenerateStructured(ctx context.Context, req GenRequest, out any) error {
	req.Structured = true
	attempts := r.maxRetry + 1
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			req.Messages = append(req.Messages, Message{Role: RoleUser,
				Content: fmt.Sprintf("Your previous output was not valid JSON matching the schema (%v). Return ONLY corrected JSON, no prose.", lastErr)})
		}
		resp, err := r.Generate(ctx, req)
		if err != nil {
			lastErr = err
			continue
		}
		text := stripJSONFence(resp.Text)
		if err := json.Unmarshal([]byte(text), out); err != nil {
			lastErr = fmt.Errorf("invalid JSON: %w", err)
			continue
		}
		return nil
	}
	return fmt.Errorf("structured generation failed after %d attempts: %w", attempts, lastErr)
}

func stripJSONFence(s string) string {
	s = trimSpace(s)
	if hasPrefix(s, "```") {
		if idx := indexOf(s, "\n"); idx >= 0 {
			s = s[idx+1:]
		}
		if idx := lastIndexOf(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	return trimSpace(s)
}

// small local helpers to avoid strings import churn
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func lastIndexOf(s, sub string) int {
	for i := len(s) - len(sub); i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

var _ = time.Second
