package retrieval

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/incidentgraph/incidentgraph/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenAIEmbedderFailureReturnsError_NoSilentFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"provider down"}`))
	}))
	defer srv.Close()

	e := NewOpenAIEmbedder(srv.URL, "key", "text-embedding-3-small", 1536)
	if e.Degraded() {
		t.Fatal("default embedder must not be in degraded fallback mode")
	}
	_, err := e.Embed(context.Background(), "pool exhausted after deploy")
	if err == nil {
		t.Fatal("real-embedding failure MUST return an error, never silently fall back")
	}
}

func TestOpenAIEmbedderExplicitFallbackIsDegradedHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	e := NewOpenAIEmbedder(srv.URL, "key", "text-embedding-3-small", 1536)
	e.EnableExplicitHashFallback()
	if !e.Degraded() {
		t.Fatal("explicitly configured fallback must report degraded")
	}
	vec, err := e.Embed(context.Background(), "some text")
	if err != nil || len(vec) != 1536 {
		t.Fatalf("explicit fallback should still produce hash vectors: len=%d err=%v", len(vec), err)
	}
	// Identity must differ from a real provider so identity checks fire.
	if e.Name() == "hash-v1" {
		t.Fatal("openai embedder name must remain provider-scoped for identity tracking")
	}
}

func TestEmbeddingIdentityMismatchFailsSearch(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()

	hashEmb := NewHashEmbedder(1536)
	store := NewStore(pool, hashEmb)
	ctx := context.Background()
	if _, _, err := store.Ingest(ctx, DocumentInput{
		SourceType: "runbook", Service: "checkout", Path: "x.md", Title: "x",
		RawContent: "# t\n\nconnection pool content here",
	}); err != nil {
		t.Fatal(err)
	}

	// Query with a DIFFERENT embedding space: must fail clearly, never return
	// garbage similarity scores across incompatible vector spaces.
	fake := NewOpenAIEmbedder("http://unused", "k", "other-model", 1536)
	mixed := NewStore(pool, &identityOverride{Embedder: fake, name: "openai:other-model"})
	_, err := mixed.SearchVector(ctx, "pool exhausted", 5)
	if err == nil || !contains(err.Error(), "embedding identity mismatch") {
		t.Fatalf("cross-space search must fail with explicit error, got %v", err)
	}
	// Same embedder continues to work.
	if _, err := store.SearchVector(ctx, "pool exhausted", 5); err != nil {
		t.Fatalf("matching-identity search failed: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOfSub(s, sub) >= 0)
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.Open(t)
}

// identityOverride pins an embedder's reported identity (for mismatch tests).
type identityOverride struct {
	Embedder
	name string
}

func (o *identityOverride) Name() string { return o.name }
