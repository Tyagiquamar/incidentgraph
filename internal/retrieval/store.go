package retrieval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/incidentgraph/incidentgraph/internal/ids"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store owns ingestion and search over document_chunks.
type Store struct {
	Pool     *pgxpool.Pool
	Embedder Embedder
}

// Embedding returns the configured embedder.
func (s *Store) Embedding() Embedder { return s.Embedder }

// embedQuery embeds a query with explicit error propagation.
func (s *Store) embedQuery(ctx context.Context, q string) (string, error) {
	vec, err := s.Embedder.Embed(ctx, q)
	if err != nil {
		return "", fmt.Errorf("embed query: %w", err)
	}
	return VectorLiteral(vec), nil
}

func NewStore(pool *pgxpool.Pool, emb Embedder) *Store {
	return &Store{Pool: pool, Embedder: emb}
}

// DocumentInput is a normalized raw document entering the pipeline:
// raw -> normalize -> classify -> chunk -> metadata -> embedding -> postgres.
type DocumentInput struct {
	SourceType string // markdown|log|runbook|postmortem|git_diff|source_code|metrics|json
	Service    string
	Path       string
	Title      string
	TrustLevel model.TrustLevel
	RawContent string
	Metadata   map[string]any
}

func ContentHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Ingest chunks + embeds a document and persists it idempotently (by content hash).
// Returns document id, chunk count.
func (s *Store) Ingest(ctx context.Context, in DocumentInput) (string, int, error) {
	if in.TrustLevel == "" {
		in.TrustLevel = model.TrustInternalDoc
	}
	docHash := ContentHash(in.SourceType + "|" + in.Path + "|" + in.RawContent)
	var docID string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM documents WHERE content_hash=$1`, docHash).Scan(&docID)
	if err == nil {
		var n int
		_ = s.Pool.QueryRow(ctx, `SELECT count(*) FROM document_chunks WHERE document_id=$1`, docID).Scan(&n)
		return docID, n, nil // already ingested
	}
	if err != nil && !strings.Contains(err.Error(), "no rows") {
		return "", 0, fmt.Errorf("lookup document: %w", err)
	}
	docID = ids.New()
	metaJSON, _ := json.Marshal(orEmptyMap(in.Metadata))
	if _, err := s.Pool.Exec(ctx, `INSERT INTO documents
		(id, source_type, service, path, title, trust_level, content_hash, raw_content, metadata,
		 embedding_provider, embedding_model, embedding_dim)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		docID, in.SourceType, in.Service, in.Path, in.Title, string(in.TrustLevel), docHash, in.RawContent, metaJSON,
		s.Embedder.Name(), s.Embedder.Name(), s.Embedder.Dim()); err != nil {
		return "", 0, fmt.Errorf("insert document: %w", err)
	}
	chunks := ChunkDocument(in.SourceType, NormalizeText(in.RawContent), ChunkOptions{ServiceName: in.Service})
	for _, ch := range chunks {
		chunkHash := ContentHash(ch.Content)
		tokens := ApproxTokens(ch.Content)
		chunkMeta, _ := json.Marshal(mergeMeta(map[string]any{
			"source_type": in.SourceType,
			"service":     in.Service,
			"path":        in.Path,
			"timestamp":   "",
			"trust_level": string(in.TrustLevel),
			"title":       in.Title,
		}, ch.Metadata))
		vec, err := s.Embedder.Embed(ctx, ch.Content)
		if err != nil {
			return docID, len(chunks), fmt.Errorf("embed chunk %d of %s: %w", ch.ChunkIndex, in.Path, err)
		}
		if _, err := s.Pool.Exec(ctx, `INSERT INTO document_chunks
			(id, document_id, chunk_index, content, content_hash, token_count, embedding, metadata)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			ids.New(), docID, ch.ChunkIndex, ch.Content, chunkHash, tokens,
			VectorLiteral(vec), chunkMeta); err != nil {
			return docID, len(chunks), fmt.Errorf("insert chunk: %w", err)
		}
	}
	return docID, len(chunks), nil
}

// ---------------------------------------------------------------- search

const (
	// Hybrid scoring is explicit and documented (docs/architecture.md#hybrid-scoring):
	//
	//   lex_norm  = lexical_score / (lexical_score + LEX_K)   (saturating, monotonic)
	//   vec_sim   = clamp(cosine(query, chunk), 0, 1)         (embeddings are L2-normalized)
	//   combined  = W_LEXICAL*lex_norm + W_VECTOR*vec_sim
	LEX_K      = 1.0
	W_LEXICAL  = 0.45
	W_VECTOR   = 0.55
	candidateN = 50
)

type rowScanner interface{ Scan(dest ...any) error }

// scanChunk maps the shared 6-column projection used by lexical/vector queries.
func scanChunk(rows rowScanner) (model.RetrievalResult, json.RawMessage, error) {
	var r model.RetrievalResult
	var meta []byte
	if err := rows.Scan(&r.ChunkID, &r.DocumentID, &r.Text, &meta, &meta, &r.CombinedScore); err != nil {
		return r, nil, err
	}
	r.Metadata = json.RawMessage(meta)
	return r, json.RawMessage(meta), nil
}

func (s *Store) SearchLexical(ctx context.Context, q string, limit int) ([]model.RetrievalResult, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT c.id, c.document_id, c.content,
		       jsonb_build_object('source_type', d.source_type, 'service', d.service,
		                          'path', d.path, 'trust_level', d.trust_level),
		       c.metadata,
		       ts_rank(c.tsv, websearch_to_tsquery('english', $1)) AS rank_score
		FROM document_chunks c JOIN documents d ON d.id = c.document_id
		WHERE c.tsv @@ websearch_to_tsquery('english', $1)
		ORDER BY rank_score DESC LIMIT $2`, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RetrievalResult
	for rows.Next() {
		var r model.RetrievalResult
		var rawScore float64
		var meta []byte
		if err := rows.Scan(&r.ChunkID, &r.DocumentID, &r.Text, &meta, &meta, &rawScore); err != nil {
			return nil, err
		}
		r.LexicalScore = rawScore
		r.Metadata = json.RawMessage(meta)
		out = append(out, r)
	}
	return out, rows.Err()
}

// checkEmbeddingIdentity refuses to query a corpus that was indexed with a
// different embedding provider/model/dimension than the current query embedder.
// Mixing embedding spaces silently produces garbage similarity scores.
func (s *Store) checkEmbeddingIdentity(ctx context.Context) error {
	rows, err := s.Pool.Query(ctx,
		`SELECT DISTINCT embedding_provider, embedding_model, embedding_dim FROM documents LIMIT 5`)
	if err != nil {
		return nil // identity columns absent (old schema): nothing to verify
	}
	defer rows.Close()
	var providers []string
	for rows.Next() {
		var prov, mdl string
		var dim int
		if err := rows.Scan(&prov, &mdl, &dim); err != nil {
			return nil
		}
		if dim != s.Embedder.Dim() || prov != s.Embedder.Name() {
			providers = append(providers, fmt.Sprintf("%s/%s/dim%d", prov, mdl, dim))
		}
	}
	if len(providers) > 0 {
		return fmt.Errorf(
			"embedding identity mismatch: corpus indexed with %v but queries use %s/dim%d; reindex the corpus before searching",
			providers, s.Embedder.Name(), s.Embedder.Dim())
	}
	return nil
}

func (s *Store) SearchVector(ctx context.Context, q string, limit int) ([]model.RetrievalResult, error) {
	if err := s.checkEmbeddingIdentity(ctx); err != nil {
		return nil, err
	}
	qv, err := s.embedQuery(ctx, q)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT c.id, c.document_id, c.content,
		       jsonb_build_object('source_type', d.source_type, 'service', d.service,
		                          'path', d.path, 'trust_level', d.trust_level),
		       c.metadata,
		       1 - (c.embedding <=> $1::vector) AS cos_sim
		FROM document_chunks c JOIN documents d ON d.id = c.document_id
		WHERE c.embedding IS NOT NULL
		ORDER BY c.embedding <=> $1::vector LIMIT $2`, qv, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.RetrievalResult
	for rows.Next() {
		var r model.RetrievalResult
		var cosSim float64
		var meta []byte
		if err := rows.Scan(&r.ChunkID, &r.DocumentID, &r.Text, &meta, &meta, &cosSim); err != nil {
			return nil, err
		}
		r.VectorScore = cosSim
		r.Metadata = json.RawMessage(meta)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SearchHybrid merges lexical and vector candidates with documented scoring.
func (s *Store) SearchHybrid(ctx context.Context, q string, limit int) ([]model.RetrievalResult, error) {
	lex, err := s.SearchLexical(ctx, q, candidateN)
	if err != nil {
		return nil, err
	}
	vec, err := s.SearchVector(ctx, q, candidateN)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.RetrievalResult{}
	order := []string{}
	add := func(r model.RetrievalResult) {
		existing, ok := byID[r.ChunkID]
		if !ok {
			cp := r
			byID[r.ChunkID] = &cp
			order = append(order, r.ChunkID)
			return
		}
		existing.LexicalScore = maxFloat(existing.LexicalScore, r.LexicalScore)
		existing.VectorScore = maxFloat(existing.VectorScore, r.VectorScore)
	}
	for _, r := range lex {
		add(r)
	}
	for _, r := range vec {
		add(r)
	}
	out := make([]model.RetrievalResult, 0, len(order))
	for _, id := range order {
		r := *byID[id]
		lexNorm := r.LexicalScore / (r.LexicalScore + LEX_K)
		vs := clamp01(r.VectorScore)
		r.CombinedScore = W_LEXICAL*lexNorm + W_VECTOR*vs
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CombinedScore > out[j].CombinedScore })
	if len(out) > limit {
		out = out[:limit]
	}
	for i := range out {
		out[i].Rank = i + 1
	}
	return out, nil
}

// Rerank applies the optional term-coverage reranking stage:
//
//	reranked = 0.7*combined + 0.3*coverage, coverage = fraction of query terms present in chunk text.
//
// This is a deterministic heuristic reranker (not a cross-encoder); the benchmark
// measures whether it helps.
func Rerank(q string, results []model.RetrievalResult, limit int) []model.RetrievalResult {
	terms := tokenizeLower(q)
	out := make([]model.RetrievalResult, len(results))
	copy(out, results)
	for i := range out {
		text := strings.ToLower(out[i].Text)
		hits := 0
		for _, t := range terms {
			if strings.Contains(text, t) {
				hits++
			}
		}
		coverage := 0.0
		if len(terms) > 0 {
			coverage = float64(hits) / float64(len(terms))
		}
		out[i].CombinedScore = 0.7*out[i].CombinedScore + 0.3*coverage
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CombinedScore > out[j].CombinedScore })
	if len(out) > limit {
		out = out[:limit]
	}
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

func tokenizeLower(s string) []string {
	f := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	stop := map[string]bool{"the": true, "a": true, "an": true, "of": true, "to": true, "in": true, "on": true, "is": true, "are": true, "and": true, "or": true, "after": false}
	var out []string
	for _, x := range f {
		if len(x) > 1 && !stop[x] {
			out = append(out, x)
		}
	}
	return out
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
