// Command bench-retrieval measures lexical / vector / hybrid / hybrid+rerank
// retrieval against the judged query set in datasets/retrieval/queries.json.
//
// Requires a seeded database (run ./cmd/seed first).
//
//	go run ./cmd/bench-retrieval -queries datasets/retrieval/queries.json -out docs/retrieval-benchmark.md
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
)

type queryCase struct {
	Q        string   `json:"q"`
	Relevant []string `json:"relevant"`
}

type perMode struct {
	Recall5   float64        `json:"recall@5"`
	Recall10  float64        `json:"recall@10"`
	MRR       float64        `json:"mrr"`
	P50MS     float64        `json:"p50_latency_ms"`
	P95MS     float64        `json:"p95_latency_ms"`
	Latencies []float64      `json:"-"`
	Hits      map[string]int `json:"-"`
}

func main() {
	queriesPath := flag.String("queries", "datasets/retrieval/queries.json", "judged queries")
	outPath := flag.String("out", "docs/retrieval-benchmark.md", "markdown output path")
	k := flag.Int("k", 10, "evaluation depth")
	flag.Parse()

	raw, err := os.ReadFile(*queriesPath)
	if err != nil {
		fatal("%v", err)
	}
	var cases []queryCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		fatal("parse queries: %v", err)
	}

	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		fatal("bootstrap: %v", err)
	}
	ctx := context.Background()

	modes := []string{"lexical", "vector", "hybrid", "rerank"}
	stats := map[string]*perMode{}
	for _, m := range modes {
		stats[m] = &perMode{Hits: map[string]int{}}
	}

	for _, qc := range cases {
		relevant := map[string]bool{}
		for _, p := range qc.Relevant {
			relevant[p] = true
		}
		for _, mode := range modes {
			started := time.Now()
			res, err := search(ctx, sys, mode, qc.Q, *k)
			latMs := float64(time.Since(started).Microseconds()) / 1000.0
			st := stats[mode]
			if err != nil {
				fatal("%s: %v", mode, err)
			}
			st.Latencies = append(st.Latencies, latMs)
			hitsAt5, hitsAt10 := 0, 0
			rr := 0.0
			seenPath := map[string]bool{}
			for i, r := range res {
				meta := map[string]any{}
				_ = json.Unmarshal(r.Metadata, &meta)
				path, _ := meta["path"].(string)
				if !relevant[path] || seenPath[path] {
					continue
				}
				seenPath[path] = true // one hit per distinct relevant document
				if i < 5 {
					hitsAt5++
				}
				hitsAt10++
				if rr == 0 {
					rr = 1.0 / float64(i+1)
				}
			}
			if hitsAt5 > 0 {
				st.Hits["r5"]++
			}
			if hitsAt10 > 0 {
				st.Hits["r10"]++
			}
			st.Recall5 += float64(hitsAt5) / float64(len(qc.Relevant))
			st.Recall10 += float64(hitsAt10) / float64(len(qc.Relevant))
			st.MRR += rr
		}
	}

	n := float64(len(cases))
	for _, st := range stats {
		st.Recall5 /= n
		st.Recall10 /= n
		st.MRR /= n
		sort.Float64s(st.Latencies)
		st.P50MS = percentile(st.Latencies, 0.50)
		st.P95MS = percentile(st.Latencies, 0.95)
	}

	// markdown report
	var b strings.Builder
	b.WriteString("# Retrieval Benchmark\n\n")
	b.WriteString("> Populated from an actual benchmark run — never hand-edited.\n\n")
	b.WriteString(fmt.Sprintf("- Queries: %d (datasets/retrieval/queries.json)\n", len(cases)))
	b.WriteString(fmt.Sprintf("- Corpus: synthetic incident corpora ingested via cmd/seed\n"))
	b.WriteString(fmt.Sprintf("- Embedder: %s (dim %d)\n", sys.Retrieval.Embedding().Name(), sys.Retrieval.Embedding().Dim()))
	b.WriteString(fmt.Sprintf("- Date: %s\n\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString("| Mode | Recall@5 | Recall@10 | MRR | p50 (ms) | p95 (ms) |\n")
	b.WriteString("|------|----------|-----------|-----|----------|----------|\n")
	for _, m := range modes {
		st := stats[m]
		b.WriteString(fmt.Sprintf("| %s | %.3f | %.3f | %.3f | %.1f | %.1f |\n",
			m, st.Recall5, st.Recall10, st.MRR, st.P50MS, st.P95MS))
	}
	b.WriteString("\nHybrid scoring: combined = " + fmt.Sprintf("%.2f", 0.45) + "*lex_norm + " + fmt.Sprintf("%.2f", 0.55) +
		"*cos_sim where lex_norm = ts_rank/(ts_rank+1). See internal/retrieval/store.go.\n")

	md := b.String()
	fmt.Print(md)
	if *outPath != "" {
		if err := os.WriteFile(*outPath, []byte(md), 0644); err != nil {
			fatal("write out: %v", err)
		}
	}
	_ = model.New
}

func search(ctx context.Context, sys *bootstrap.System, mode, q string, k int) ([]model.RetrievalResult, error) {
	switch mode {
	case "lexical":
		return sys.Retrieval.SearchLexical(ctx, q, k)
	case "vector":
		return sys.Retrieval.SearchVector(ctx, q, k)
	case "hybrid":
		return sys.Retrieval.SearchHybrid(ctx, q, k)
	default:
		res, err := sys.Retrieval.SearchHybrid(ctx, q, k*2)
		if err != nil {
			return nil, err
		}
		return retrieval.Rerank(q, res, k), nil
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func fatal(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "bench-retrieval: "+f+"\n", args...)
	os.Exit(1)
}
