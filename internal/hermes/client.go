// Package hermes is the optional Hermes agent adapter.
//
// Hermes stays OPTIONAL: IncidentGraph never depends on it at runtime. The
// adapter maps Hermes lifecycle events onto IncidentGraph AgentRuns by
// exposing our tools to Hermes through the incidentgraph-mcp server and
// recording run state in Postgres. No Hermes internals are forked or copied;
// when HermesBaseURL is unreachable the adapter reports a degraded state.
package hermes

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/observability"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	log     *observability.Logger
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 15 * time.Second},
		log:     observability.New("hermes"),
	}
}

// StartRequest asks Hermes to begin processing an existing IncidentGraph run;
// the run row already exists so Postgres remains the source of truth.
type StartRequest struct {
	RunID      string   `json:"run_id"`
	IncidentID string   `json:"incident_id"`
	Task       string   `json:"task"`
	MCPServer  string   `json:"mcp_server"` // URL of incidentgraph-mcp
	Tools      []string `json:"tools"`      // explicit allowlist
}

type StartResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

func (c *Client) Start(ctx context.Context, req StartRequest) (*StartResponse, error) {
	return post[StartResponse](ctx, c, "/api/runs/start", req)
}

// Stop terminates the Hermes-side session; run lifecycle remains ours.
func (c *Client) Stop(ctx context.Context, sessionID string) error {
	_, err := post[map[string]any](ctx, c, "/api/runs/"+sessionID+"/stop", map[string]any{})
	return err
}

// SessionStatus fetches the current status and event log of a Hermes session
// into out (decoded JSON). Used by the HermesAgentRunner poll loop.
func (c *Client) SessionStatus(ctx context.Context, sessionID string, out any) error {
	return getJSON(ctx, c, "/api/runs/"+sessionID, out)
}

// Healthy pings Hermes. Adapters must degrade explicitly when absent.
func (c *Client) Healthy(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func post[T any](ctx context.Context, c *Client, path string, body any) (*T, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hermes unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("hermes http %d: %s", resp.StatusCode, string(raw))
	}
	var out T
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func getJSON(ctx context.Context, c *Client, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("hermes unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("hermes http %d for %s", resp.StatusCode, path)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out)
}
