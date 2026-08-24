// Package evals implements the evaluation platform: versioned case datasets,
// deterministic + rubric + trajectory graders, an optional LLM judge, suite
// execution with regression gates, and the security red-team suite.
package evals

import (
	"encoding/json"
	"fmt"
)

// Case is one evaluation scenario.
type Case struct {
	Slug                  string   `json:"slug"`
	Title                 string   `json:"title"`
	Service               string   `json:"service"`
	Severity              string   `json:"severity"`
	Description           string   `json:"description"`
	ExpectedRootCause     string   `json:"expected_root_cause"`
	AcceptableRootCauses  []string `json:"acceptable_root_causes"`
	RequiredEvidenceTypes []string `json:"required_evidence_types"`
	ExpectedTools         []string `json:"expected_tools"`
	ForbiddenTools        []string `json:"forbidden_tools"`
	ForbiddenActions      []string `json:"forbidden_actions"`
	DistractorPaths       []string `json:"distractor_paths"`
	SeedCorpus            bool     `json:"seed_corpus"`
	CorpusDir             string   `json:"corpus_dir,omitempty"` // subdir under datasets/incidents/

	// seededPaths is populated at runtime by the runner when this case's
	// corpus was ingested; recorded in score details for provenance.
	seededPaths []string
}

// Score is the graded outcome for one case (mirrors DB eval_scores).
type Score struct {
	EvalRunID              string          `json:"-"`
	CaseSlug               string          `json:"case_slug"`
	TaskSuccess            bool            `json:"task_success"`
	RootCauseScore         float64         `json:"root_cause_score"`
	EvidenceScore          float64         `json:"evidence_score"`
	ToolAccuracy           float64         `json:"tool_accuracy"`
	UnsafeActionCount      int             `json:"unsafe_action_count"`
	HallucinatedClaimCount int             `json:"hallucinated_claim_count"`
	UnnecessaryToolCalls   int             `json:"unnecessary_tool_calls"`
	LatencyMS              int64           `json:"latency_ms"`
	TotalTokens            int64           `json:"total_tokens"`
	CostCents              float64         `json:"cost_cents"`
	Details                json.RawMessage `json:"details"`
}

// Totals aggregates a suite run.
type Totals struct {
	CaseCount           int     `json:"case_count"`
	SuccessRate         float64 `json:"success_rate"`
	MeanRootCauseScore  float64 `json:"mean_root_cause_score"`
	MeanEvidenceScore   float64 `json:"mean_evidence_score"`
	MeanToolAccuracy    float64 `json:"tool_accuracy"`
	UnsafeActions       int     `json:"unsafe_actions"`
	HallucinatedClaims  int     `json:"hallucinated_claims"`
	P50LatencyMS        int64   `json:"p50_latency_ms"`
	P95LatencyMS        int64   `json:"p95_latency_ms"`
	MeanCostCents       float64 `json:"mean_cost_cents"`
	MeanTokens          float64 `json:"mean_tokens"`
	InjectionResistance float64 `json:"injection_resistance"`
}

// Regression compares candidate totals against a baseline.
type Regression struct {
	BaselineRunID    string   `json:"baseline_eval_run_id,omitempty"`
	BaselineSuccess  float64  `json:"baseline_success"`
	CandidateSuccess float64  `json:"candidate_success"`
	SuccessDelta     float64  `json:"success_delta"`
	UnsafeDelta      int      `json:"unsafe_delta"`
	Passed           bool     `json:"passed"`
	Reasons          []string `json:"reasons,omitempty"`
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func pct(f float64) float64 { return f }

var _ = fmt.Sprintf
