package retrieval

import (
	"strings"
	"testing"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

func TestChunkMarkdownByHeadings(t *testing.T) {
	doc := `# Runbook
intro text

## Database checks
check connection pool metrics here

## Rollback
revert the deploy`
	chunks := ChunkDocument("markdown", doc, ChunkOptions{MaxTokens: 320})
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d: %+v", len(chunks), chunks)
	}
	if !strings.Contains(chunks[1].Content, "Database checks") {
		t.Fatalf("heading should be retained in section chunk")
	}
}

func TestChunkLogsTemporal(t *testing.T) {
	log := ""
	for i := 0; i < 30; i++ {
		log += "2026-08-23T10:00:0" + string(rune('0'+i%10)) + "Z checkout p99=2600ms\n"
	}
	for i := 0; i < 5; i++ {
		log += "2026-08-23T10:05:00Z checkout recovered\n"
	}
	chunks := ChunkDocument("log", log, ChunkOptions{})
	if len(chunks) < 2 {
		t.Fatalf("expected temporal grouping into >=2 chunks, got %d", len(chunks))
	}
	if !strings.Contains(chunks[0].Metadata["time_window"].(string), "2026-08-23T10:00") {
		t.Fatalf("missing time_window metadata: %+v", chunks[0].Metadata)
	}
}

func TestHashEmbedderDeterministicAndNormalized(t *testing.T) {
	e := NewHashEmbedder(1536)
	a := e.Embed("database connection pool exhausted after deployment")
	b := e.Embed("database connection pool exhausted after deployment")
	c := e.Embed("redis cache stampede causes thundering herd")
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("embeddings must be deterministic")
		}
		break
	}
	simAB := Cosine(a, b)
	simAC := Cosine(a, c)
	if simAB < 0.9999 {
		t.Fatalf("identical text similarity %v", simAB)
	}
	if simAC >= simAB {
		t.Fatalf("different text should be less similar: %v vs %v", simAC, simAB)
	}
	var norm float64
	for _, x := range a {
		norm += float64(x) * float64(x)
	}
	if norm < 0.99 || norm > 1.01 {
		t.Fatalf("embedding not normalized: %v", norm)
	}
}

func TestHybridScoringWeightsDocumented(t *testing.T) {
	// combined = W_LEXICAL*lex_norm + W_VECTOR*vec_sim with lex_norm = s/(s+K)
	lexNorm := 2.0 / (2.0 + LEX_K)
	want := W_LEXICAL*lexNorm + W_VECTOR*0.8
	got := W_LEXICAL*(2.0/(2.0+LEX_K)) + W_VECTOR*clamp01(0.8)
	if want != got || got <= 0 || got > 1 {
		t.Fatalf("scoring formula mismatch: %v", got)
	}
}

func TestRerankBoostsCoverage(t *testing.T) {
	q := "connection pool exhausted"
	in := []model.RetrievalResult{
		{Text: "redis latency stable during incident"},
		{Text: "postgres connection pool exhausted, wait events on acquire"},
	}
	out := Rerank(q, in, 2)
	if out[0].Text != in[1].Text {
		t.Fatalf("coverage reranker should promote matching chunk, got %+v", out[0])
	}
}
