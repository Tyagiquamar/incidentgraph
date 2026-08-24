// Command mcp-server exposes allowlisted IncidentGraph tools over MCP
// (JSON-RPC 2.0, HTTP transport) so external agent engines — Hermes, Claude,
// Cursor — can investigate incidents through OUR policy layer.
//
// Auth: Bearer IG_MCP_TOKEN (constant-time compare). Production fails closed
// unless auth is enabled. See internal/mcpserver for the full hardening model.
package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/mcpserver"
	"github.com/incidentgraph/incidentgraph/internal/observability"
)

var log = observability.New("mcp-server")

func main() {
	cfg := config.Load()
	addr := flag.String("addr", cfg.MCPAddr, "listen address")
	flag.Parse()

	if cfg.Env == "production" && !cfg.MCPAuthEnabled {
		log.Error("refusing to start: production requires IG_MCP_AUTH_ENABLED=true", observability.F{})
		os.Exit(1)
	}
	if !cfg.MCPAuthEnabled {
		log.Warn("mcp auth DISABLED — acceptable only for local development", observability.F{"env": cfg.Env})
	}

	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		log.Error("bootstrap failed", observability.F{"error": err.Error()})
		os.Exit(1)
	}

	// Explicit read-only allowlist. WRITE/PRIVILEGED tools stay in the core
	// product behind human approval; they are never exposed over MCP.
	handler, err := mcpserver.Handler(mcpserver.Deps{
		Tools:       sys.Tools,
		Policy:      sys.Policy,
		Pool:        sys.Pool,
		AuthEnabled: cfg.MCPAuthEnabled,
		AuthToken:   cfg.MCPAuthToken,
		Allowlist: map[string]bool{
			"search_docs":             true,
			"search_logs":             true,
			"search_code":             true,
			"get_deployment":          true,
			"get_git_diff":            true,
			"read_file":               true,
			"query_metrics":           true,
			"query_postgres_readonly": true,
		},
	})
	if err != nil {
		log.Error("invalid mcp configuration", observability.F{"error": err.Error()})
		os.Exit(1)
	}

	srv := &http.Server{Addr: *addr, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second}
	log.Info("mcp server listening", observability.F{"addr": *addr, "auth_enabled": cfg.MCPAuthEnabled, "env": cfg.Env})
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("stopped", observability.F{"error": err.Error()})
		os.Exit(1)
	}
}
