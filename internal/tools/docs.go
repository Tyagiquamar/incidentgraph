package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type deps struct {
	Pool *pgxpool.Pool
	Ret  *retrieval.Store
}

func newDeps(pool *pgxpool.Pool, ret *retrieval.Store) deps { return deps{pool, ret} }

type docRecord struct {
	ID         string          `json:"id"`
	SourceType string          `json:"source_type"`
	Service    string          `json:"service"`
	Path       string          `json:"path"`
	Title      string          `json:"title"`
	TrustLevel string          `json:"trust_level"`
	Content    string          `json:"content"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

func fetchDocsByPath(ctx context.Context, pool *pgxpool.Pool, likePattern string, limit int) ([]docRecord, error) {
	if limit <= 0 {
		limit = 3
	}
	rows, err := pool.Query(ctx, `SELECT id, source_type, service, path, title, trust_level, raw_content, metadata
	    FROM documents WHERE path LIKE $1 ORDER BY created_at DESC LIMIT $2`, likePattern, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDocs(rows)
}

func fetchDocsExact(ctx context.Context, pool *pgxpool.Pool, path string) ([]docRecord, error) {
	rows, err := pool.Query(ctx, `SELECT id, source_type, service, path, title, trust_level, raw_content, metadata
	    FROM documents WHERE path = $1 ORDER BY created_at DESC LIMIT 1`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectDocs(rows)
}

func collectDocs(rows pgx.Rows) ([]docRecord, error) {
	var out []docRecord
	for rows.Next() {
		var d docRecord
		if err := rows.Scan(&d.ID, &d.SourceType, &d.Service, &d.Path, &d.Title,
			&d.TrustLevel, &d.Content, &d.Metadata); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func docsToJSON(docs []docRecord) json.RawMessage {
	b, _ := json.Marshal(docs)
	return b
}

func renderDocs(docs []docRecord) string {
	s := ""
	for i, d := range docs {
		s += fmt.Sprintf("[%d] %s (%s)\n%s\n\n", i+1, d.Path, d.TrustLevel, d.Content)
	}
	return s
}
