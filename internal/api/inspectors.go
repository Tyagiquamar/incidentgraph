package api

import (
	"encoding/json"
	"net/http"

	"github.com/incidentgraph/incidentgraph/internal/auth"
	"github.com/incidentgraph/incidentgraph/internal/memory"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
)

// requireRole guards a route by role.
func (s *Server) requireRole(required auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return s.cfg.Auth.Middleware(required, next)
	}
}

// ---------------------------------------------------------------- documents & retrieval

func (s *Server) ingestDocument(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SourceType string         `json:"source_type"`
		Service    string         `json:"service"`
		Path       string         `json:"path"`
		Title      string         `json:"title"`
		TrustLevel string         `json:"trust_level"`
		Content    string         `json:"content"`
		Metadata   map[string]any `json:"metadata"`
	}
	if err := decodeBody(r, &in); err != nil {
		s.err(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if in.Content == "" || in.Path == "" {
		s.err(w, http.StatusBadRequest, "content and path required")
		return
	}
	docID, chunks, err := s.retrieval.Ingest(r.Context(), retrieval.DocumentInput{
		SourceType: in.SourceType, Service: in.Service, Path: in.Path,
		Title: in.Title, TrustLevel: model.TrustLevel(in.TrustLevel),
		RawContent: in.Content, Metadata: in.Metadata,
	})
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"document_id": docID, "chunks": chunks})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Query string `json:"query"`
		K     int    `json:"k"`
		Mode  string `json:"mode"` // lexical|vector|hybrid|rerank
	}
	if err := decodeBody(r, &in); err != nil {
		s.err(w, http.StatusBadRequest, "invalid body")
		return
	}
	if in.Query == "" {
		s.err(w, http.StatusBadRequest, "query required")
		return
	}
	if in.K <= 0 || in.K > 50 {
		in.K = 8
	}
	ctx := r.Context()
	var results []model.RetrievalResult
	var err error
	switch in.Mode {
	case "lexical":
		results, err = s.retrieval.SearchLexical(ctx, in.Query, in.K)
	case "vector":
		results, err = s.retrieval.SearchVector(ctx, in.Query, in.K)
	case "rerank", "hybrid+rerank":
		results, err = s.retrieval.SearchHybrid(ctx, in.Query, in.K*2)
		if err == nil {
			results = retrieval.Rerank(in.Query, results, in.K)
		}
	default: // hybrid
		results, err = s.retrieval.SearchHybrid(ctx, in.Query, in.K)
	}
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if results == nil {
		results = []model.RetrievalResult{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"query": in.Query, "mode": modeOrDefault(in.Mode), "results": results})
}

func modeOrDefault(m string) string {
	if m == "" {
		return "hybrid"
	}
	return m
}

func (s *Server) searchModes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		s.err(w, http.StatusBadRequest, "q required")
		return
	}
	ctx := r.Context()
	k := queryInt(r, "k", 6)
	out := map[string]any{}
	for _, mode := range []string{"lexical", "vector", "hybrid"} {
		var res []model.RetrievalResult
		var err error
		switch mode {
		case "lexical":
			res, err = s.retrieval.SearchLexical(ctx, q, k)
		case "vector":
			res, err = s.retrieval.SearchVector(ctx, q, k)
		default:
			res, err = s.retrieval.SearchHybrid(ctx, q, k)
		}
		if err != nil {
			s.err(w, http.StatusInternalServerError, mode+": "+err.Error())
			return
		}
		if res == nil {
			res = []model.RetrievalResult{}
		}
		out[mode] = res
	}
	reranked := retrieval.Rerank(q, out["hybrid"].([]model.RetrievalResult), k)
	out["rerank"] = reranked
	b, _ := json.Marshal(out)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// ---------------------------------------------------------------- memory inspector

func (s *Server) workingMemory(w http.ResponseWriter, r *http.Request) {
	items, err := s.memory.Working(r.Context(), r.PathValue("runId"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []memory.Item{}
	}
	s.writeJSON(w, http.StatusOK, items)
}

func (s *Server) memorySearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		s.err(w, http.StatusBadRequest, "q required")
		return
	}
	episodic, _ := s.memory.EpisodicRecent(r.Context(), 10)
	semantic, err := s.memory.SemanticSearch(r.Context(), q, 8)
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"episodic_recent":  orEmptyItems(episodic),
		"semantic_matches": orEmptyItems(semantic),
		"note":             "memory is untrusted context; shown for inspection only",
	})
}

func orEmptyItems(items any) any { return items }

// ---------------------------------------------------------------- security

func (s *Server) securityEvents(w http.ResponseWriter, r *http.Request) {
	runID := r.URL.Query().Get("run_id")
	var (
		events []model.SecurityEvent
		err    error
	)
	if runID != "" {
		events, err = s.security.ListForRun(r.Context(), runID, queryInt(r, "limit", 200))
	} else {
		events, err = s.security.ListRecent(r.Context(), queryInt(r, "limit", 100))
	}
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []model.SecurityEvent{}
	}
	s.writeJSON(w, http.StatusOK, events)
}
