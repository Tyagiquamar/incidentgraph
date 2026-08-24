// Package durablemcp is the IncidentGraph integration client for the
// DurableMCP durable-execution substrate.
//
// Flow: IncidentGraph persists a tool_call row, then submits the invocation
// over MCP HTTP (JSON-RPC tools/call) with a stable idempotency key. DurableMCP
// owns lease/fencing, retries and the event log; IncidentGraph polls the read
// API for terminal state and stores the execution ID on its tool_call row so
// traces can link step -> durable execution -> event timeline.
//
// If DurableMCP is unavailable, calls that REQUIRE durability fail with an
// explicit degraded state — they are never silently executed outside the
// durable path.
package durablemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL   string
	ReaderKey string
	HTTP      *http.Client
}

func New(baseURL, readerKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{BaseURL: baseURL, ReaderKey: readerKey, HTTP: &http.Client{Timeout: timeout}}
}

// ---------------------------------------------------------------- MCP wire types

type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int64          `json:"id"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// SubmitResult is the synchronous response of tools/call: DurableMCP
// persists + dispatches asynchronously.
type SubmitResult struct {
	ExecutionID string `json:"execution_id"`
	Status      string `json:"status"`
	Duplicate   bool   `json:"duplicate"`
}

// Execution mirrors the REST read model of DurableMCP.
type Execution struct {
	ID             string          `json:"id"`
	Namespace      string          `json:"namespace"`
	ToolName       string          `json:"tool_name"`
	IdempotencyKey string          `json:"idempotency_key"`
	InputArgs      json.RawMessage `json:"input_args"`
	Status         string          `json:"status"`
	Attempts       int             `json:"attempts"`
	MaxAttempts    int             `json:"max_attempts"`
	Result         json.RawMessage `json:"result,omitempty"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type Event struct {
	ID           int64           `json:"id"`
	ExecutionID  string          `json:"execution_id"`
	EventType    string          `json:"event_type"`
	WorkerID     string          `json:"worker_id,omitempty"`
	FencingToken *int64          `json:"fencing_token,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	OccurredAt   time.Time       `json:"occurred_at"`
}

// Terminal statuses reported by DurableMCP.
func IsTerminal(status string) bool {
	switch status {
	case "completed", "failed", "cancelled", "dead", "exhausted":
		return true
	}
	return false
}

// ---------------------------------------------------------------- operations

var rpcIDCounter int64 = time.Now().UnixNano()

func (c *Client) callMCP(ctx context.Context, method string, params map[string]any) (json.RawMessage, error) {
	rpcIDCounter++
	reqBody := rpcRequest{JSONRPC: "2.0", ID: rpcIDCounter, Method: method, Params: params}
	b, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/mcp", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("durablemcp unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("durablemcp http %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}
	var rr rpcResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("durablemcp bad json-rpc: %w", err)
	}
	if rr.Error != nil {
		return nil, fmt.Errorf("durablemcp rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	return rr.Result, nil
}

// Initialize performs the MCP handshake; used by health checks.
func (c *Client) Initialize(ctx context.Context) error {
	_, err := c.callMCP(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "incidentgraph", "version": "0.1.0"},
	})
	return err
}

// Healthy reports whether DurableMCP answers the handshake.
func (c *Client) Healthy(ctx context.Context) bool {
	hctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return c.Initialize(hctx) == nil
}

// Submit submits a durable tool invocation. namespace scopes executions;
// idemKey must be stable across retries (we use the IncidentGraph tool_call ID).
func (c *Client) Submit(ctx context.Context, namespace, tool string, args json.RawMessage, idemKey string) (*SubmitResult, error) {
	params := map[string]any{
		"name":      tool,
		"arguments": json.RawMessage(args),
		"_meta": map[string]any{
			"idempotency_key": idemKey,
			"namespace":       namespace,
		},
	}
	raw, err := c.callMCP(ctx, "tools/call", params)
	if err != nil {
		return nil, err
	}
	var out SubmitResult
	if err := json.Unmarshal(raw, &out); err != nil || out.ExecutionID == "" {
		// tolerate wrapped content shapes
		var wrapper struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err2 := json.Unmarshal(raw, &wrapper); err2 == nil && len(wrapper.Content) > 0 {
			if err3 := json.Unmarshal([]byte(wrapper.Content[0].Text), &out); err3 == nil && out.ExecutionID != "" {
				return &out, nil
			}
		}
		return nil, fmt.Errorf("durablemcp submit: unexpected result %s", truncateStr(string(raw), 200))
	}
	return &out, nil
}

func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	if c.ReaderKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.ReaderKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("durablemcp api unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("durablemcp api http %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}

// Get fetches one execution by ID.
func (c *Client) Get(ctx context.Context, execID string) (*Execution, error) {
	var e Execution
	if err := c.getJSON(ctx, "/api/v1/executions/"+execID, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Events returns the immutable event timeline of an execution.
func (c *Client) Events(ctx context.Context, execID string) ([]Event, error) {
	var out struct {
		Events []Event `json:"events"`
	}
	// tolerate both bare-array and {events:[]} shapes
	if err := c.getJSON(ctx, "/api/v1/executions/"+execID+"/events", &out); err != nil {
		var arr []Event
		if err2 := c.getJSON(ctx, "/api/v1/executions/"+execID+"/events", &arr); err2 == nil {
			return arr, nil
		}
		return nil, err
	}
	return out.Events, nil
}

// PollUntilDone polls until terminal state or timeout. Poll interval starts at
// 100ms and doubles to 1s max.
func (c *Client) PollUntilDone(ctx context.Context, execID string, timeout time.Duration) (*Execution, error) {
	deadline := time.Now().Add(timeout)
	interval := 100 * time.Millisecond
	for {
		e, err := c.Get(ctx, execID)
		if err != nil {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("poll deadline exceeded waiting for %s: %w", execID, err)
			}
		} else if IsTerminal(e.Status) {
			return e, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			return e, fmt.Errorf("durablemcp execution %s not terminal after %s (status=%s)", execID, timeout, statusOf(e))
		}
		time.Sleep(interval)
		if interval < time.Second {
			interval *= 2
		}
	}
}

func statusOf(e *Execution) string {
	if e == nil {
		return "<unknown>"
	}
	return e.Status
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
