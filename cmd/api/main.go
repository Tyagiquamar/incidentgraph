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
)

var log = observability.New("api")

func main() {
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Error("invalid configuration; refusing to start", observability.F{"error": err.Error()})
		os.Exit(1)
	}
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
	backends := map[string]agent.Runner{"native-v1": sys.Native}
	if cfg.HermesEnabled {
		backends["hermes"] = hermes.NewRunner(hermes.NewClient(cfg.HermesBaseURL), sys.Runs,
			cfg.MCPPublicURL, cfg.MCPAuthToken, sys.Tools.Names())
		log.Info("hermes backend enabled", observability.F{"url": cfg.HermesBaseURL, "mcp": cfg.MCPPublicURL})
	}

	srv := api.NewServer(api.ServerConfig{
		Auth: auth.Config{
			Enabled:       cfg.AuthEnabled,
			AdminToken:    cfg.AdminToken,
			OperatorToken: cfg.OperatorToken,
			ViewerToken:   cfg.ViewerToken,
		},
		DurableURL: cfg.DurableMCPURL,
		Backends:   backends,
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

	resumeActive(ctx, sys)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	log.Info("shutdown complete", observability.F{})
}

// resumeActive re-drives runnable runs left by a previous process. The runner
// acquires its own fenced lease inside Resume (single ownership path); a live
// worker that claimed the run first simply wins the race.
// needs_approval runs are NOT resumed automatically: they wait for a human
// decision via POST /approvals/{id}/approve|reject.
func resumeActive(ctx context.Context, sys *bootstrap.System) {
	for {
		ids, err := sys.Runs.ClaimableRunIDs(ctx, 8)
		if err != nil {
			log.Warn("resume scan failed", observability.F{"error": err.Error()})
			return
		}
		if len(ids) == 0 {
			return
		}
		for _, id := range ids {
			go func(runID string) {
				bg := context.Background()
				if err := sys.Native.Resume(bg, runID); err != nil {
					log.Info("resume not taken", observability.F{"run_id": runID, "reason": err.Error()})
				} else {
					log.Info("resumed run after restart", observability.F{"run_id": runID})
				}
			}(id)
		}
		return
	}
}
