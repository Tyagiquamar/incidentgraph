// Command evals runs the evaluation suite and/or the security red-team suite
// against a live IncidentGraph database. Exit code 1 on regression or security
// failure so CI can gate on it.
//
// Usage:
//
//	go run ./cmd/evals -mode eval -backend native-v1 [-baseline <eval_run_id>]
//	go run ./cmd/evals -mode security
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	evalsdata "github.com/incidentgraph/incidentgraph/datasets/evals"
	injdata "github.com/incidentgraph/incidentgraph/datasets/injections"
	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/evals"
)

func fatal(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "evals: "+f+"\n", args...)
	os.Exit(1)
}

// datasetIncidentsDir resolves datasets/incidents relative to this module
// (works from repo root and from within cmd/evals).
func datasetIncidentsDir() string {
	for _, cand := range []string{"datasets/incidents", "../datasets/incidents", "../../datasets/incidents"} {
		if st, err := os.Stat(cand); err == nil && st.IsDir() {
			return cand
		}
	}
	return ""
}

func main() {
	mode := flag.String("mode", "eval", "eval|security|smoke")
	backend := flag.String("backend", "native-v1", "agent backend under test")
	baseline := flag.String("baseline", "", "baseline eval run id for regression gate")
	slugs := flag.String("cases", "", "smoke mode: comma-separated case slugs (default 5 representative)")
	flag.Parse()

	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		fatal("bootstrap: %v", err)
	}

	switch *mode {
	case "security":
		fixtures, err := injdata.Load()
		if err != nil {
			fatal("load fixtures: %v", err)
		}
		fs := make([]evals.InjectionFixture, len(fixtures))
		for i, f := range fixtures {
			fs[i] = evals.InjectionFixture{
				Slug: f.Slug, SourceType: f.SourceType, Content: f.Content,
				ExpectedCategory: f.ExpectedCategory, MustNotExecuteTool: f.MustNotExecuteTool,
				MaliciousSQL: f.MaliciousSQL, MaliciousArgs: f.MaliciousArgs,
			}
		}
		res, err := evals.RunSecuritySuite(sys.Pool, fs)
		if err != nil {
			fatal("security suite: %v", err)
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		if !res.Passed {
			os.Exit(1)
		}

	case "eval":
		cases, err := evalsdata.Load()
		if err != nil {
			fatal("load cases: %v", err)
		}
		judge := evals.NewLLMJudge(sys.LLM)
		runner := evals.NewRunner(sys.Runs, sys.Native, sys.Retrieval, sys.Memory, sys.Pool, sys.Retrieval.Embedding())
		runner.Cases = cases
		runner.Judge = judge
		runner.DatasetRoot = datasetIncidentsDir()
		outAny, err := runner.RunSuite(*backend, *baseline)
		if err != nil {
			fatal("run suite: %v", err)
		}
		out, _ := json.MarshalIndent(outAny, "", "  ")
		fmt.Println(string(out))
		if m, ok := outAny.(map[string]any); ok {
			if reg, ok := m["regression"].(evals.Regression); ok && !reg.Passed {
				os.Exit(1)
			}
			if tot, ok := m["totals"].(evals.Totals); ok && tot.UnsafeActions > 0 {
				os.Exit(1) // security regressions fail immediately
			}
		}

	case "smoke":
		// REAL-MODEL SMOKE (manual, never in CI): requires real provider
		// credentials; results are reported separately from the mock
		// deterministic baseline and must never be compared as one series.
		if cfg.LLMProvider != "openai" || cfg.LLMAPIKey == "" {
			fatal("smoke mode requires IG_LLM_PROVIDER=openai and IG_LLM_API_KEY")
		}
		cases, err := evalsdata.Load()
		if err != nil {
			fatal("load cases: %v", err)
		}
		want := map[string]bool{}
		if *slugs != "" {
			for _, s := range strings.Split(*slugs, ",") {
				want[strings.TrimSpace(s)] = true
			}
		}
		if len(want) == 0 {
			for _, c := range cases {
				switch c.Slug {
				case "db-pool-regression", "n-plus-one-query", "cache-stampede",
					"prompt-injection-runbook", "insufficient-evidence-abstain":
					want[c.Slug] = true
				}
			}
		}
		var subset []evals.Case
		for _, c := range cases {
			if want[c.Slug] {
				subset = append(subset, c)
			}
		}
		if len(subset) == 0 {
			fatal("no matching cases for smoke subset")
		}
		runner := evals.NewRunner(sys.Runs, sys.Native, sys.Retrieval, sys.Memory, sys.Pool, sys.Retrieval.Embedding())
		runner.Cases = subset
		runner.Judge = evals.NewLLMJudge(sys.LLM)
		runner.DatasetRoot = datasetIncidentsDir()
		outAny, err := runner.RunSuite("native-v1", "")
		if err != nil {
			fatal("smoke suite: %v", err)
		}
		out, _ := json.MarshalIndent(outAny, "", "  ")
		fmt.Println(string(out))

	default:
		fatal("unknown mode %q", *mode)
	}
}
