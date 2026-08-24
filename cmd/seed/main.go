// Command seed loads the synthetic demo corpora into the database:
// incidents, runbooks, logs, metrics, deployments and diffs.
//
//	go run ./cmd/seed -datasets datasets/incidents
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/ingest"
)

func main() {
	datasets := flag.String("datasets", "datasets/incidents", "path to incident scenario dirs")
	flag.Parse()

	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: bootstrap: %v\n", err)
		os.Exit(1)
	}
	results, err := ingest.LoadCorpus(context.Background(), sys.Retrieval, *datasets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "seed: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(out))

	failed := false
	for _, r := range results {
		if len(r.Errors) > 0 {
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
}
