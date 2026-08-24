// Package mcpserver implements the incidentgraph-mcp HTTP handler: an
// authenticated, hardened MCP (JSON-RPC 2.0 over HTTP) endpoint exposing ONLY
// explicitly allowlisted read-only tools through the deterministic policy
// engine. External engines (Hermes etc.) call this instead of touching the
// database directly.
package mcpserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/incidentgraph/incidentgraph/internal/tools"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MaxRequestBody = 1 << 20 // 1 MiB
	RPCTimeout     = 45 * time.Second
	MaxResultText  = 32000
)

// JSON-RPC 2.0 error codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
)

// Deps bundles what the handler needs; all fields are required except Pool.
type Deps struct {
	Tools       *tools.Registry
	Policy      *policy.Engine
	Pool        *pgxpool.Pool // security_events sink for denied calls; optional
	AuthEnabled bool
	AuthToken   string

	// Allowlist is the explicit set of tool names exposed over MCP. Anything
	// absent is denied regardless of registry contents.
	Allowlist map[string]bool
}

func (d *Deps) validate() error {
	if d.Tools == nil || d.Policy == nil {
		return errors.New("mcpserver: Tools and Policy are required")
	}
	if len(d.Allowlist) == 0 {
		return errors.New("mcpserver: empty allowlist")
	}
	for name := range d.Allowlist {
		exec, ok := d.Tools.Get(name)
		if !ok {
			return fmt.Errorf("mcpserver: allowlisted tool %q missing from registry", name)
		}
		if exec.Def().Risk == model.RiskWrite || exec.Def().Risk == model.RiskPrivilege {
			return fmt.Errorf("mcpserver: %s tools must never be exposed over MCP", name)
		}
	}
	return nil
}

// Handler builds the authenticated /mcp HTTP handler plus unauthenticated
// /healthz on the same mux.
func Handler(deps Deps) (http.Handler, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("POST /mcp", authMiddleware(deps, rpcBodyGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), RPCTimeout)
		defer cancel()
		handleRPC(ctx, &deps, w, r)
	}))))
	return mux, nil
}

func authMiddleware(deps Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !deps.AuthEnabled || deps.AuthToken == "" {
			next.ServeHTTP(w, r) // dev mode only; production validation forbids this
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(auth, prefix)), []byte(deps.AuthToken)) != 1 {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func rpcBodyGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBody)
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			writeRPCError(w, nil, CodeInvalidRequest, "Content-Type must be application/json")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

// ---------------------------------------------------------------- wire types

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

func handleRPC(ctx context.Context, deps *Deps, w http.ResponseWriter, r *http.Request) {
	var req rpcReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPCError(w, nil, CodeParseError, "parse error")
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeRPCError(w, req.ID, CodeInvalidRequest, "invalid JSON-RPC request")
		return
	}
	switch req.Method {
	case "initialize":
		writeRPCResult(w, req.ID, map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "incidentgraph-mcp", "version": "0.2.0"},
		})
	case "tools/list":
		defs := []map[string]any{}
		for _, d := range deps.Tools.Definitions() {
			if !deps.Allowlist[d.Name] {
				continue
			}
			defs = append(defs, map[string]any{
				"name":        d.Name,
				"description": d.Description + " [risk: " + string(d.Risk) + ", policy-enforced]",
				"inputSchema": d.InputSchema,
			})
		}
		writeRPCResult(w, req.ID, map[string]any{"tools": defs})
	case "tools/call":
		handleToolCall(ctx, deps, w, r, &req)
	default:
		writeRPCError(w, req.ID, CodeMethodNotFound, "method not found")
	}
}

func handleToolCall(ctx context.Context, deps *Deps, w http.ResponseWriter, r *http.Request, req *rpcReq) {
	name := req.Params.Name
	if name == "" {
		writeRPCError(w, req.ID, CodeInvalidParams, "params.name is required")
		return
	}
	if !deps.Allowlist[name] {
		recordDenied(deps.Pool, name, "not on MCP allowlist")
		writeRPCResult(w, req.ID, map[string]any{
			"content": []map[string]string{{"type": "text", "text": "DENIED: tool not allowlisted"}},
			"isError": true,
		})
		return
	}
	exec, ok := deps.Tools.Get(name)
	if !ok {
		writeRPCError(w, req.ID, CodeInvalidParams, "unknown tool")
		return
	}
	decision := deps.Policy.Evaluate(name, req.Params.Arguments)
	if decision.Decision != model.PolicyAllowed {
		recordDenied(deps.Pool, name, decision.Reason)
		writeRPCResult(w, req.ID, map[string]any{
			"content": []map[string]string{{"type": "text", "text": "DENIED by policy: " + decision.Reason}},
			"isError": true,
		})
		return
	}
	result, err := exec.Execute(ctx, "", security.RedactJSON(req.Params.Arguments))
	if err != nil {
		writeRPCResult(w, req.ID, map[string]any{
			"content": []map[string]string{{"type": "text", "text": "tool error: " + err.Error()}},
			"isError": true,
		})
		return
	}
	text := result.Text
	if len(text) > MaxResultText {
		text = text[:MaxResultText]
	}
	writeRPCResult(w, req.ID, map[string]any{
		"content": []map[string]string{{"type": "text", "text": text}},
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	writeRPC(w, id, &rpcErr{Code: code, Message: msg})
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeRPC(w, id, result)
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

func recordDenied(pool *pgxpool.Pool, tool, reason string) {
	if pool == nil {
		return
	}
	_, _ = pool.Exec(context.Background(),
		`INSERT INTO security_events (source, category, detected_content, decision)
		 VALUES ('model_output','policy_denied_tool_request',$1,'blocked')`, tool+" :: "+reason)
}
