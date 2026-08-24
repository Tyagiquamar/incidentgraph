package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

func timeNow() time.Time { return time.Now() }

const timeSecond = 60 * time.Second

// synthesizeArgs deterministically derives tool arguments from the incident
// and previously observed results. The native runner keeps argument planning
// deterministic so trajectories are auditable; the LLM handles reasoning
// tasks (plan/hypotheses/verify/report) instead.
func synthesizeArgs(tool string, inc *model.Incident, prior []model.ToolCall) json.RawMessage {
	kw := keywords(inc.Title+" "+inc.Description, 6)
	query := strings.Join(kw, " ")
	switch tool {
	case "search_docs":
		return marshal(map[string]any{"query": query, "k": 6})
	case "search_logs":
		return marshal(map[string]any{"query": inc.Service + " " + query, "k": 8})
	case "search_code":
		return marshal(map[string]any{"query": query, "k": 5})
	case "get_deployment":
		return marshal(map[string]any{"service": inc.Service, "limit": 2})
	case "get_git_diff":
		return marshal(map[string]any{"path_or_commit": inc.Service})
	case "read_file":
		if p := referencedDocPath(prior); p != "" {
			return marshal(map[string]any{"path": p})
		}
		return nil
	case "query_metrics":
		return marshal(map[string]any{"series": metricSeriesFor(inc), "service": inc.Service})
	case "query_postgres_readonly":
		lower := strings.ToLower(inc.Description)
		if strings.Contains(lower, "database") || strings.Contains(lower, "connection") || strings.Contains(lower, "pool") {
			return marshal(map[string]any{
				"sql": fmt.Sprintf("SELECT id, title, service, severity FROM incidents WHERE service = '%s' ORDER BY created_at DESC LIMIT 10", sanitizeSQLLiteral(inc.Service))})
		}
		return nil
	case "restart_service":
		return marshal(map[string]any{"service": inc.Service, "reason": "remediation for incident: " + inc.Title})
	default:
		return nil // unknown/unplanned tools are skipped by the deterministic planner
	}
}

func referencedDocPath(prior []model.ToolCall) string {
	for i := len(prior) - 1; i >= 0; i-- {
		tc := prior[i]
		if tc.Status == "succeeded" && tc.ResultReference != "" &&
			strings.Contains(tc.ResultReference, "/") && !strings.HasPrefix(tc.ResultReference, "durablemcp:") {
			return tc.ResultReference
		}
	}
	return ""
}

func metricSeriesFor(inc *model.Incident) string {
	lower := strings.ToLower(inc.Title + " " + inc.Description)
	switch {
	case strings.Contains(lower, "database") || strings.Contains(lower, "db") ||
		strings.Contains(lower, "pool") || strings.Contains(lower, "connection"):
		return "db_wait_ms"
	case strings.Contains(lower, "redis") || strings.Contains(lower, "cache"):
		return "redis_latency_ms"
	case strings.Contains(lower, "backlog") || strings.Contains(lower, "lag") ||
		strings.Contains(lower, "consumer"):
		return "queue_lag"
	default:
		return "p99_latency_ms"
	}
}

func sanitizeSQLLiteral(s string) string {
	s = strings.ReplaceAll(s, "'", "''")
	s = strings.ReplaceAll(s, ";", "")
	return s
}
