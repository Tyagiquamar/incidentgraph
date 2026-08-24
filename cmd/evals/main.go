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
	mode := flag.String("mode", "eval", "eval|security")
	backend := flag.String("backend", "native-v1", "agent backend under test")
	baseline := flag.String("baseline", "", "baseline eval run id for regression gate")
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

	default:
		fatal("unknown mode %q", *mode)
	}
}
