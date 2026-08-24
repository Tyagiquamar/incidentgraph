package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/auth"
	"github.com/incidentgraph/incidentgraph/internal/durablemcp"
	"github.com/incidentgraph/incidentgraph/internal/model"
)

// contextDetach returns a background context for async run execution.
func contextDetach() context.Context { return context.Background() }

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func supportsFlush(w http.ResponseWriter) (http.Flusher, bool) {
	f, ok := w.(http.Flusher)
	return f, ok
}

// authRoleName returns the authenticated principal's display name for audit
// attribution (approvals.decided_by). Falls back to "unknown" when the auth
// middleware did not run.
func authRoleName(r *http.Request) string {
	if p := auth.FromContext(r.Context()); p != nil && p.Name != "" {
		return p.Name
	}
	return "unknown"
}

var _ = json.Marshal
var _ = time.Now

// durableClient is wired by NewServerWithDurable for tool-call drill-down.
type durableClient = durablemcp.Client

func (s *Server) durableRef(r *http.Request, tc *model.ToolCall) any {
	if s.durable == nil {
		return map[string]string{"status": "unconfigured"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	exec, err := s.durable.Get(ctx, tc.DurableExecutionID)
	if err != nil {
		return map[string]string{"error": err.Error(), "execution_id": tc.DurableExecutionID}
	}
	events, _ := s.durable.Events(ctx, tc.DurableExecutionID)
	return map[string]any{"execution": exec, "events": events}
}
