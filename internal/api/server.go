// Package api implements the IncidentGraph HTTP API: incidents, runs, SSE
// event streaming, approvals, retrieval inspector, evals and security events.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/agent"
	"github.com/incidentgraph/incidentgraph/internal/auth"
	"github.com/incidentgraph/incidentgraph/internal/durablemcp"
	"github.com/incidentgraph/incidentgraph/internal/evidence"
	"github.com/incidentgraph/incidentgraph/internal/memory"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/openclaw"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	cfg           ServerConfig
	pool          *pgxpool.Pool
	runs          *runs.Store
	evidence      *evidence.Store
	memory        *memory.Store
	retrieval     *retrieval.Store
	security      *security.Store
	runner        agent.Runner // native engine
	hermes        agent.Runner // optional hermes engine (nil unless configured)
	openclaw      *openclaw.Gateway
	openclawToken string
	durable       *durablemcp.Client
	log           *observability.Logger
}

type ServerConfig struct {
	Auth        auth.Config
	MaxToolCall int
	MaxSteps    int
	DurableURL  string
	Hermes      agent.Runner // optional backend; nil unless configured
}

func NewServer(cfg ServerConfig, pool *pgxpool.Pool, ret *retrieval.Store,
	mem *memory.Store, sec *security.Store, nativeRunner agent.Runner) *Server {
	s := &Server{
		cfg: cfg, pool: pool,
		runs:      runs.NewStore(pool),
		evidence:  evidence.NewStore(pool),
		memory:    mem,
		retrieval: ret,
		security:  sec,
		runner:    nativeRunner,
		log:       observability.New("api"),
	}
	if cfg.Hermes != nil {
		s.hermes = cfg.Hermes
	}
	if cfg.DurableURL != "" {
		s.durable = durablemcp.New(cfg.DurableURL, "", 10*time.Second)
	}
	return s
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("write json", observability.F{"error": err.Error()})
	}
}

func (s *Server) err(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}

// Mux builds the route table using Go 1.22+ enhanced ServeMux patterns.
func (s *Server) Handler() http.Handler {
	muxRaw := http.NewServeMux()

	// health
	muxRaw.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.pool.Ping(r.Context()); err != nil {
			s.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "degraded", "database": err.Error()})
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// incidents
	muxRaw.Handle("POST /incidents", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.createIncident)))
	muxRaw.Handle("GET /incidents", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.listIncidents)))
	muxRaw.Handle("GET /incidents/{id}", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.getIncident)))
	muxRaw.Handle("POST /incidents/{id}/runs", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.startRun)))

	// runs & trace
	muxRaw.Handle("GET /runs/{id}", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.getRun)))
	muxRaw.Handle("GET /runs/{id}/steps", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runSteps)))
	muxRaw.Handle("GET /runs/{id}/tool-calls", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runToolCalls)))
	muxRaw.Handle("GET /runs/{id}/tool-calls/{callId}", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.toolCallDetail)))
	muxRaw.Handle("GET /runs/{id}/hypotheses", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runHypotheses)))
	muxRaw.Handle("GET /runs/{id}/evidence", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runEvidence)))
	muxRaw.Handle("GET /runs/{id}/graph", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runGraph)))
	muxRaw.Handle("GET /runs/{id}/model-usage", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runModelUsage)))
	muxRaw.Handle("POST /runs/{id}/cancel", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.cancelRun)))

	// events: snapshot + SSE stream (persist-before-stream; replay via ?since=)
	muxRaw.Handle("GET /runs/{id}/events", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.runEvents)))

	// approvals
	muxRaw.Handle("POST /approvals/{id}/approve", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.approveApproval)))
	muxRaw.Handle("POST /approvals/{id}/reject", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.rejectApproval)))

	// documents & search
	muxRaw.Handle("POST /documents", s.requireRole(auth.RoleOperator)(http.HandlerFunc(s.ingestDocument)))
	muxRaw.Handle("POST /search", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.search)))
	muxRaw.Handle("GET /search/modes", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.searchModes)))

	// memory inspector
	muxRaw.Handle("GET /memory/working/{runId}", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.workingMemory)))
	muxRaw.Handle("GET /memory/search", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.memorySearch)))

	// security
	muxRaw.Handle("GET /security/events", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.securityEvents)))

	// evals
	muxRaw.Handle("GET /evals", s.requireRole(auth.RoleViewer)(http.HandlerFunc(s.listEvals)))
	muxRaw.Handle("POST /evals/run", s.requireRole(auth.RoleAdmin)(http.HandlerFunc(s.runEvals)))

	// optional OpenClaw messaging ingress (auth via verify token, not roles)
	muxRaw.HandleFunc("POST /openclaw/webhook", s.openclawWebhook)

	return s.withLogging(muxRaw)
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trace := observability.NewTraceID()
		w.Header().Set("X-Trace-Id", trace)
		start := startClock()
		next.ServeHTTP(w, r)
		s.log.Info("http", observability.F{
			"trace_id": trace, "method": r.Method, "path": r.URL.Path,
			"duration_ms": sinceMS(start),
		})
	})
}
