package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxRows is the concrete rows type from the pool.
type pgxRows = interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

func resultsToOutput(results []model.RetrievalResult) []map[string]any {
	out := make([]map[string]any, 0, len(results))
	for _, r := range results {
		out = append(out, map[string]any{
			"chunk_id":       r.ChunkID,
			"document_id":    r.DocumentID,
			"text":           r.Text,
			"combined_score": r.CombinedScore,
			"metadata":       r.Metadata,
		})
	}
	return out
}

func resultsText(results []model.RetrievalResult) string {
	var b strings.Builder
	for i, r := range results {
		meta := map[string]any{}
		_ = json.Unmarshal(r.Metadata, &meta)
		fmt.Fprintf(&b, "[%d] %s (%v)\n%s\n\n", i+1, meta["path"], meta["trust_level"], r.Text)
	}
	return b.String()
}

// ---------------------------------------------------------------- search_docs

type SearchDocs struct{ d deps }

func NewSearchDocs(pool *pgxpool.Pool, ret *retrieval.Store) *SearchDocs {
	return &SearchDocs{newDeps(pool, ret)}
}

func (t *SearchDocs) Def() Definition {
	return Definition{
		Name:        "search_docs",
		Description: "Hybrid (lexical+vector) semantic search over runbooks, postmortems and documentation.",
		InputSchema: schema(map[string]any{
			"query": sProp("natural-language query"),
			"k":     map[string]any{"type": "integer", "description": "max results (default 6)"},
		}, []string{"query"}),
		Risk:    model.RiskReadOnly,
		Timeout: 15 * time.Second,
	}
}

func (t *SearchDocs) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	q := strArg(args, "query")
	if q == "" {
		return nil, fmt.Errorf("query required")
	}
	res, err := t.d.Ret.SearchHybrid(ctx, q, intArg(args, "k", 6))
	if err != nil {
		return nil, err
	}
	return &Result{Output: mustJSON(map[string]any{"query": q, "matches": resultsToOutput(res)}),
		Text: resultsText(res), Reference: topHitPath(res)}, nil
}

// topHitPath returns the document path of the best hit so tool calls carry an
// inspectable provenance reference (empty when there were no hits).
func topHitPath(results []model.RetrievalResult) string {
	if len(results) == 0 {
		return ""
	}
	var meta map[string]any
	if json.Unmarshal(results[0].Metadata, &meta) != nil {
		return ""
	}
	p, _ := meta["path"].(string)
	return p
}

// ---------------------------------------------------------------- search_logs

type SearchLogs struct{ SearchDocs }

func NewSearchLogs(pool *pgxpool.Pool, ret *retrieval.Store) *SearchLogs {
	return &SearchLogs{*NewSearchDocs(pool, ret)}
}

func (t *SearchLogs) Def() Definition {
	d := t.SearchDocs.Def()
	d.Name = "search_logs"
	d.Description = "Search application logs by keyword or semantics; returns grouped log lines with time windows."
	return d
}

// ---------------------------------------------------------------- search_code

type SearchCode struct{ SearchDocs }

func NewSearchCode(pool *pgxpool.Pool, ret *retrieval.Store) *SearchCode {
	return &SearchCode{*NewSearchDocs(pool, ret)}
}

func (t *SearchCode) Def() Definition {
	d := t.SearchDocs.Def()
	d.Name = "search_code"
	d.Description = "Search indexed source code snippets by concept, symbol or error string."
	return d
}

// ---------------------------------------------------------------- get_deployment

type GetDeployment struct{ d deps }

func NewGetDeployment(pool *pgxpool.Pool, ret *retrieval.Store) *GetDeployment {
	return &GetDeployment{newDeps(pool, ret)}
}

func (t *GetDeployment) Def() Definition {
	return Definition{
		Name:        "get_deployment",
		Description: "Return recent deployment records (config changes, commits) for a service.",
		InputSchema: schema(map[string]any{
			"service": sProp("service name, e.g. checkout"),
			"limit":   map[string]any{"type": "integer"},
		}, []string{"service"}),
		Risk:    model.RiskReadOnly,
		Timeout: 10 * time.Second,
	}
}

func (t *GetDeployment) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	svc := strArg(args, "service")
	if svc == "" {
		return nil, fmt.Errorf("service required")
	}
	docs, err := fetchDocsByPath(ctx, t.d.Pool, "deployments/"+svc+"/%", intArg(args, "limit", 3))
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no deployment records for %q", svc)
	}
	return &Result{Output: docsToJSON(docs), Text: renderDocs(docs), Reference: "deployments/" + svc}, nil
}

// ---------------------------------------------------------------- get_git_diff

type GetGitDiff struct{ d deps }

func NewGetGitDiff(pool *pgxpool.Pool, ret *retrieval.Store) *GetGitDiff {
	return &GetGitDiff{newDeps(pool, ret)}
}

func (t *GetGitDiff) Def() Definition {
	return Definition{
		Name:        "get_git_diff",
		Description: "Fetch a stored commit/diff record by commit hash or path fragment.",
		InputSchema: schema(map[string]any{
			"path_or_commit": sProp(`e.g. "commits/checkout/d38ac2" or just "d38ac2"`),
		}, []string{"path_or_commit"}),
		Risk:    model.RiskReadOnly,
		Timeout: 10 * time.Second,
	}
}

func (t *GetGitDiff) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	key := strArg(args, "path_or_commit")
	if key == "" {
		return nil, fmt.Errorf("path_or_commit required")
	}
	pattern := key + "%"
	if !strings.Contains(key, "/") {
		pattern = "%" + key + "%"
	}
	docs, err := fetchDocsByPath(ctx, t.d.Pool, pattern, 5)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no commit record matching %q", key)
	}
	return &Result{Output: docsToJSON(docs), Text: renderDocs(docs), Reference: docs[0].Path}, nil
}

// ---------------------------------------------------------------- read_file

type ReadFile struct{ d deps }

func NewReadFile(pool *pgxpool.Pool, ret *retrieval.Store) *ReadFile {
	return &ReadFile{newDeps(pool, ret)}
}

func (t *ReadFile) Def() Definition {
	return Definition{
		Name:        "read_file",
		Description: "Read a document from the ingested corpus by exact path.",
		InputSchema: schema(map[string]any{"path": sProp("document path")}, []string{"path"}),
		Risk:        model.RiskReadOnly,
		Timeout:     10 * time.Second,
	}
}

func (t *ReadFile) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	path := strArg(args, "path")
	if path == "" {
		return nil, fmt.Errorf("path required")
	}
	docs, err := fetchDocsExact(ctx, t.d.Pool, path)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("document not found: %s", path)
	}
	return &Result{Output: docsToJSON(docs[:1]), Text: renderDocs(docs[:1]), Reference: path}, nil
}

// ---------------------------------------------------------------- query_metrics

type QueryMetrics struct{ d deps }

func NewQueryMetrics(pool *pgxpool.Pool, ret *retrieval.Store) *QueryMetrics {
	return &QueryMetrics{newDeps(pool, ret)}
}

func (t *QueryMetrics) Def() Definition {
	return Definition{
		Name:        "query_metrics",
		Description: "Query recorded metric series fixtures (latency, saturation, errors) for a service.",
		InputSchema: schema(map[string]any{
			"series":  sProp(`metric name e.g. "db_wait_ms", "p99_latency_ms", "redis_latency_ms", "cpu_pct"`),
			"service": sProp("service filter"),
		}, []string{"series", "service"}),
		Risk:    model.RiskReadOnly,
		Timeout: 10 * time.Second,
	}
}

func (t *QueryMetrics) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	series := strArg(args, "series")
	svc := strArg(args, "service")
	if series == "" || svc == "" {
		return nil, fmt.Errorf("series and service required")
	}
	docs, err := fetchDocsByPath(ctx, t.d.Pool, "metrics/"+svc+"/"+series+"%", 1)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("no metric series %q for service %q", series, svc)
	}
	var parsed any
	if json.Unmarshal([]byte(docs[0].Content), &parsed) == nil {
		return &Result{Output: mustJSON(parsed), Text: docs[0].Content, Reference: docs[0].Path}, nil
	}
	return &Result{Output: mustJSON(docs[0].Content), Text: docs[0].Content, Reference: docs[0].Path}, nil
}

// ---------------------------------------------------------------- query_postgres_readonly

type QueryPostgres struct {
	d       deps
	checker SQLPolicyChecker
}

// SQLPolicyChecker re-validates SQL inside the tool (defense in depth).
type SQLPolicyChecker func(sql string) error

func NewQueryPostgres(pool *pgxpool.Pool, ret *retrieval.Store, checker SQLPolicyChecker) *QueryPostgres {
	return &QueryPostgres{newDeps(pool, ret), checker}
}

func (t *QueryPostgres) Def() Definition {
	return Definition{
		Name:        "query_postgres_readonly",
		Description: "Execute a single read-only SELECT/WITH statement against the operational database. Destructive statements are blocked by the deterministic policy engine.",
		InputSchema: schema(map[string]any{"sql": sProp("single SELECT statement")}, []string{"sql"}),
		Risk:        model.RiskReadOnly,
		Timeout:     20 * time.Second,
	}
}

func (t *QueryPostgres) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	sqlStr := strArg(args, "sql")
	if sqlStr == "" {
		return nil, fmt.Errorf("sql required")
	}
	if t.checker != nil {
		if err := t.checker(sqlStr); err != nil {
			return nil, fmt.Errorf("policy violation: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, t.Def().Timeout)
	defer cancel()
	rows, err := t.d.Pool.Query(ctx, sqlStr)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	header := make([]string, len(fields))
	for i, f := range fields {
		header[i] = string(f.Name)
	}
	const limit = 50
	data := make([][]any, 0, limit)
	for rows.Next() && len(data) < limit {
		vals := make([]any, len(fields))
		ptrs := make([]any, len(fields))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]any, len(fields))
		for i, v := range vals {
			switch x := v.(type) {
			case []byte:
				row[i] = string(x)
			case time.Time:
				row[i] = x.UTC().Format(time.RFC3339)
			default:
				row[i] = v
			}
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]any{"columns": header, "rows": data, "row_count": len(data), "truncated_to": limit}
	b, _ := json.Marshal(out)
	return &Result{Output: b, Text: string(b), Reference: "sql"}, nil
}
