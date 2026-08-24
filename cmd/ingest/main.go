// Command ingest loads one document (or a directory of documents) into the
// retrieval corpus.
//
//	go run ./cmd/ingest -file runbook.md -path docs/runbook.md -type runbook -service checkout
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
)

func main() {
	file := flag.String("file", "", "file to ingest")
	path := flag.String("path", "", "logical path (defaults to -file value)")
	typ := flag.String("type", "markdown", "source_type: markdown|log|runbook|postmortem|git_diff|source_code|metrics|json")
	service := flag.String("service", "", "owning service")
	trust := flag.String("trust", string(model.TrustInternalDoc), "trust level")
	flag.Parse()

	if *file == "" {
		fmt.Fprintln(os.Stderr, "ingest: -file required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
		os.Exit(1)
	}
	logicalPath := *path
	if logicalPath == "" {
		logicalPath = *file
	}

	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest: bootstrap: %v\n", err)
		os.Exit(1)
	}
	docID, chunks, err := sys.Retrieval.Ingest(context.Background(), retrieval.DocumentInput{
		SourceType: *typ,
		Service:    *service,
		Path:       logicalPath,
		Title:      logicalPath,
		TrustLevel: model.TrustLevel(*trust),
		RawContent: string(raw),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.Marshal(map[string]any{"document_id": docID, "chunks": chunks})
	fmt.Println(string(out))
}
