// Package tools defines the IncidentGraph tool system: explicit definitions,
// risk levels, and deterministic executors. Tools never self-authorize; every
// call passes through the policy engine before execution.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

// Result is a normalized tool output.
type Result struct {
	Output    json.RawMessage `json:"output"`              // structured result
	Text      string          `json:"text"`                // flattened form for context assembly
	Reference string          `json:"reference,omitempty"` // path/commit/execution reference
	SizeBytes int             `json:"size_bytes"`
}

// Definition is the explicit contract of one tool.
type Definition struct {
	Name        string
	Description string
	InputSchema map[string]any
	Risk        model.RiskLevel
	Timeout     time.Duration
	Durable     bool // must execute through the DurableMCP substrate
}

// Executor runs one tool deterministically.
type Executor interface {
	Def() Definition
	Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error)
}

// Registry holds available tools.
type Registry struct{ byName map[string]Executor }

func NewRegistry(executors ...Executor) *Registry {
	r := &Registry{byName: map[string]Executor{}}
	for _, e := range executors {
		r.byName[e.Def().Name] = e
	}
	return r
}

func (r *Registry) Get(name string) (Executor, bool) {
	e, ok := r.byName[name]
	return e, ok
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	return out
}

// Definitions returns all tool definitions (used for MCP tools/list).
func (r *Registry) Definitions() []Definition {
	out := make([]Definition, 0, len(r.byName))
	for _, e := range r.byName {
		out = append(out, e.Def())
	}
	return out
}

func strArg(args json.RawMessage, key string) string {
	var m map[string]any
	if json.Unmarshal(args, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func intArg(args json.RawMessage, key string, def int) int {
	var m map[string]any
	if json.Unmarshal(args, &m) != nil {
		return def
	}
	if v, ok := m[key].(float64); ok && v > 0 {
		return int(v)
	}
	return def
}

func schema(props map[string]any, required []string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required}
}

func sProp(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(fmt.Sprintf(`{"error":%q}`, err.Error()))
	}
	return b
}
