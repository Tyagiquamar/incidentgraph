// Command mcp-server exposes allowlisted IncidentGraph tools over MCP
// (JSON-RPC 2.0, HTTP transport) so external agent engines — Hermes, Claude,
// Cursor — can investigate incidents through OUR policy layer.
//
// Flow: MCP client -> incidentgraph-mcp -> policy engine -> (durable) execution.
// Only explicitly allowlisted tools are exposed; nothing internal leaks.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/jackc/pgx/v5/pgconn"
)

var log = observability.New("mcp-server")

var rpcID int64

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	addr := flag.String("addr", ":8765", "listen address")
	flag.Parse()

	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		log.Error("bootstrap failed", observability.F{"error": err.Error()})
		os.Exit(1)
	}

	// Explicit allowlist: read-only tools only. Risky tools stay in the core
	// product behind approval; they are never auto-exposed to MCP clients.
	allowlist := map[string]bool{
		"search_docs":             true,
		"search_logs":             true,
		"search_code":             true,
		"get_deployment":          true,
		"get_git_diff":            true,
		"read_file":               true,
		"query_metrics":           true,
		"query_postgres_readonly": true,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		var req rpcReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPC(w, nil, &rpcErr{Code: -32700, Message: "parse error"})
			return
		}
		switch req.Method {
		case "initialize":
			writeRPC(w, req.ID, map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": "incidentgraph-mcp", "version": "0.1.0"},
			})
		case "tools/list":
			defs := []map[string]any{}
			for _, d := range sys.Tools.Definitions() {
				if !allowlist[d.Name] {
					continue
				}
				defs = append(defs, map[string]any{
					"name":        d.Name,
					"description": d.Description + " [risk: " + string(d.Risk) + ", policy-enforced]",
					"inputSchema": d.InputSchema,
				})
			}
			writeRPC(w, req.ID, map[string]any{"tools": defs})
		case "tools/call":
			name := req.Params.Name
			if !allowlist[name] {
				recordDenied(sys.Pool, "", name, "not on MCP allowlist")
				writeRPC(w, req.ID, map[string]any{
					"content": []map[string]string{{"type": "text", "text": "DENIED: tool not allowlisted"}},
					"isError": true,
				})
				return
			}
			exec, ok := sys.Tools.Get(name)
			if !ok {
				writeRPC(w, req.ID, &rpcErr{Code: -32602, Message: "unknown tool"})
				return
			}
			decision := sys.Policy.Evaluate(name, req.Params.Arguments)
			if decision.Decision != model.PolicyAllowed {
				recordDenied(sys.Pool, "", name, decision.Reason)
				writeRPC(w, req.ID, map[string]any{
					"content": []map[string]string{{"type": "text", "text": "DENIED by policy: " + decision.Reason}},
					"isError": true,
				})
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), exec.Def().Timeout)
			defer cancel()
			result, err := exec.Execute(ctx, "", security.RedactJSON(req.Params.Arguments))
			if err != nil {
				writeRPC(w, req.ID, map[string]any{
					"content": []map[string]string{{"type": "text", "text": "tool error: " + err.Error()}},
					"isError": true,
				})
				return
			}
			text := result.Text
			if len(text) > 32000 {
				text = text[:32000]
			}
			writeRPC(w, req.ID, map[string]any{
				"content": []map[string]string{{"type": "text", "text": text}},
			})
		default:
			writeRPC(w, req.ID, &rpcErr{Code: -32601, Message: "method not found"})
		}
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Info("mcp server listening", observability.F{"addr": *addr, "allowlist_size": len(allowlist)})
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("stopped", observability.F{"error": err.Error()})
		os.Exit(1)
	}
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any) {
	resp := rpcResp{JSONRPC: "2.0", ID: id}
	if e, ok := result.(*rpcErr); ok {
		resp.Error = e
	} else {
		resp.Result = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func recordDenied(pool poolExec, runID, tool, reason string) {
	if pool == nil {
		return
	}
	var rid any
	if runID != "" {
		rid = runID
	}
	_, _ = pool.Exec(context.Background(),
		`INSERT INTO security_events (run_id, source, category, detected_content, decision)
		 VALUES ($1,'model_output','policy_denied_tool_request',$2,'blocked')`, rid, tool+" :: "+reason)
}

type poolExec interface {
	Exec(ctx context.Context, sql string, args ...any) (commandTag, error)
}

type commandTag = pgconn.CommandTag
