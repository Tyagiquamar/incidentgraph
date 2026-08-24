package durablemcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSubmitAndPoll exercises the client against a fake DurableMCP whose wire
// shapes mirror the real service (JSON-RPC /mcp + REST read API).
func TestSubmitAndPoll(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method != "tools/call" {
			t.Fatalf("unexpected method %s", req.Method)
		}
		writeJSON(w, map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"result": map[string]any{"execution_id": "exec-1", "status": "ready", "duplicate": false},
		})
	})
	mux.HandleFunc("GET /api/v1/executions/exec-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer reader-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]any{
			"id": "exec-1", "namespace": "incidentgraph", "tool_name": "restart_service",
			"status": "completed", "attempts": 1, "max_attempts": 3,
			"result": map[string]any{"ok": true},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := New(srv.URL, "reader-key", 5*time.Second)
	res, err := c.Submit(context.Background(), "incidentgraph", "restart_service",
		json.RawMessage(`{"service":"checkout"}`), "tc-123")
	if err != nil {
		t.Fatal(err)
	}
	if res.ExecutionID != "exec-1" || res.Status != "ready" {
		t.Fatalf("bad submit: %+v", res)
	}
	exec, err := c.PollUntilDone(context.Background(), "exec-1", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if exec.Status != "completed" {
		t.Fatalf("want completed, got %s", exec.Status)
	}
}

func TestUnreachableIsExplicitError(t *testing.T) {
	c := New("http://127.0.0.1:1", "", time.Second)
	if _, err := c.Submit(context.Background(), "ns", "t", json.RawMessage(`{}`), "k"); err == nil {
		t.Fatal("expected explicit error when DurableMCP unreachable")
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
