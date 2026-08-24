// Command api serves the IncidentGraph HTTP API and resumes any runs left
// active by a previous process (runs survive restarts).
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	evalsdata "github.com/incidentgraph/incidentgraph/datasets/evals"
	"github.com/incidentgraph/incidentgraph/internal/agent"
	"github.com/incidentgraph/incidentgraph/internal/api"
	"github.com/incidentgraph/incidentgraph/internal/auth"
	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/evals"
	"github.com/incidentgraph/incidentgraph/internal/hermes"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/openclaw"
	"github.com/incidentgraph/incidentgraph/internal/runs"
)

var log = observability.New("api")

func main() {
	cfg := config.Load()
	ctx := context.Background()

	sys, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		log.Error("bootstrap failed", observability.F{"error": err.Error()})
		os.Exit(1)
	}

	if cases, err := evalsdata.Load(); err == nil {
		runner := evals.NewRunner(sys.Runs, sys.Native, sys.Retrieval, sys.Memory, sys.Pool, sys.Retrieval.Embedding())
		runner.Cases = cases
		runner.Judge = evals.NewLLMJudge(sys.LLM)
		runner.DatasetRoot = "datasets/incidents"
		api.SetEvalsRunner(runner)
	} else {
		log.Warn("eval cases unavailable", observability.F{"error": err.Error()})
	}

	// Optional Hermes backend: selected explicitly per run via
	// {"backend":"hermes"}; never silently substituted for the native engine.
	var hermesRunner agent.Runner
	if cfg.HermesEnabled {
		mcpURL := cfg.MCPPublicURL
		hermesRunner = hermes.NewRunner(hermes.NewClient(cfg.HermesBaseURL), sys.Runs, mcpURL, sys.Tools.Names())
		log.Info("hermes backend enabled", observability.F{"url": cfg.HermesBaseURL, "mcp": mcpURL})
	}

	srv := api.NewServer(api.ServerConfig{
		Auth: auth.Config{
			Enabled:       cfg.AuthEnabled,
			AdminToken:    cfg.AdminToken,
			OperatorToken: cfg.OperatorToken,
			ViewerToken:   cfg.ViewerToken,
		},
		DurableURL: cfg.DurableMCPURL,
		Hermes:     hermesRunner,
	}, sys.Pool, sys.Retrieval, sys.Memory, sys.Security, sys.Native)

	if cfg.OpenClawIngressEnabled {
		srv.SetOpenClaw(openclaw.NewGateway(), cfg.OpenClawVerifyToken)
		log.Info("openclaw ingress enabled", observability.F{})
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("listening", observability.F{"addr": cfg.HTTPAddr})
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server stopped", observability.F{"error": err.Error()})
		}
	}()

	resumeActive(ctx, sys.Runs, sys.Native)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	log.Info("shutdown complete", observability.F{})
}

// resumeActive re-drives runs that a previous process left running. Runs are
// claimed via lease (FOR UPDATE SKIP LOCKED) so this never steals a run that
// a live worker is currently driving. needs_approval runs are NOT resumed
// automatically: they wait for a human decision via
// POST /approvals/{id}/approve|reject.
func resumeActive(ctx context.Context, rs *runs.Store, runner agentRunner) {
	for {
		run, err := rs.ClaimNext(ctx, 10*time.Minute)
		if err != nil {
			log.Warn("resume claim failed", observability.F{"error": err.Error()})
			return
		}
		if run == nil {
			return
		}
		go func(id string) {
			bg := context.Background()
			if err := runner.Resume(bg, id); err != nil {
				log.Warn("resume failed", observability.F{"run_id": id, "error": err.Error()})
			} else {
				log.Info("resumed run after restart", observability.F{"run_id": id})
			}
			_ = rs.ReleaseLease(bg, id)
		}(run.ID)
	}
}

type agentRunner interface {
	Resume(ctx context.Context, runID string) error
}
