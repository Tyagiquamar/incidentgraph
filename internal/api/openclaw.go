package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/openclaw"
)

// OpenClawIngress is the OPTIONAL messaging-gateway adapter. It translates
// inbound chat commands into the same API actions the dashboard uses — the
// gateway never becomes the runtime and holds no investigation state.
type OpenClawIngress struct {
	Gateway     *openclaw.Gateway
	VerifyToken string

	runs *runsStoreRef
}

type runsStoreRef = struct{}

// SetOpenClaw wires the optional ingress into the server.
func (s *Server) SetOpenClaw(g *openclaw.Gateway, verifyToken string) {
	s.openclaw = g
	s.openclawToken = verifyToken
}

// openclawWebhook handles POST /openclaw/webhook.
func (s *Server) openclawWebhook(w http.ResponseWriter, r *http.Request) {
	if s.openclaw == nil {
		s.err(w, http.StatusNotImplemented, "openclaw ingress not configured")
		return
	}
	if s.openclawToken != "" && r.Header.Get("X-Verify-Token") != s.openclawToken {
		s.err(w, http.StatusUnauthorized, "invalid verify token")
		return
	}
	var msg struct {
		Channel   string `json:"channel"`
		Workspace string `json:"workspace"`
		UserID    string `json:"user_id"`
		Text      string `json:"text"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err := json.Unmarshal(body, &msg); err != nil || msg.Channel == "" || msg.UserID == "" {
		s.err(w, http.StatusBadRequest, "expected {channel, workspace, user_id, text}")
		return
	}

	cmd, reply := s.openclaw.HandleCommand(r.Context(), msg.Channel, msg.Workspace, msg.UserID, msg.Text)
	if reply != nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"reply": reply.Text})
		return
	}
	if cmd == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"reply": ""})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	switch cmd.Action {
	case "investigate":
		inc := model.Incident{ID: model.New(), Title: truncTitle(cmd.Argument, 120),
			Description: cmd.Argument, Service: "unknown", Severity: "sev3", Status: "open"}
		if err := s.runs.CreateIncident(ctx, inc); err != nil {
			s.err(w, http.StatusInternalServerError, err.Error())
			return
		}
		run := model.AgentRun{ID: model.New(), IncidentID: inc.ID,
			AgentBackend: "native-v1", Status: model.RunRunning}
		if err := s.runs.CreateRun(ctx, run); err != nil {
			s.err(w, http.StatusInternalServerError, err.Error())
			return
		}
		go func() {
			bg := contextDetach()
			// runner self-claims its fenced lease (single ownership path)
			if runner, ok := s.ForBackend(run.AgentBackend); ok {
				_ = runner.Start(bg, run.ID)
			}
		}()
		s.writeJSON(w, http.StatusOK, map[string]any{
			"reply":       "Investigation started.",
			"incident_id": inc.ID, "run_id": run.ID,
		})

	case "approve", "reject":
		id := cmd.Argument
		appr, err := s.runs.GetApproval(ctx, id)
		if err != nil || appr == nil || appr.Status != "pending" {
			s.err(w, http.StatusConflict, "approval not found or already decided")
			return
		}
		status := "rejected"
		if cmd.Action == "approve" {
			status = "approved"
		}
		decidedBy := "openclaw:" + cmd.Principal.UserID
		updated, txErr := s.runs.DecideApprovalTx(ctx, id, status, decidedBy)
		if txErr != nil {
			s.err(w, http.StatusConflict, txErr.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"reply":  "Approval " + status + " by " + decidedBy,
			"run_id": appr.RunID,
		})
		_ = updated

		// Backend-aware resume dispatch; if this process loses the race to a
		// worker, the worker's fenced Resume claims the run instead.
		go func() {
			bg := contextDetach()
			runner, berr := s.backendForRun(bg, appr.RunID)
			if berr == nil {
				_ = runner.Resume(bg, appr.RunID)
			}
		}()

	case "cancel":
		if cmd.Argument == "" {
			s.err(w, http.StatusBadRequest, "cancel requires a run id")
			return
		}
		runner, berr := s.backendForRun(ctx, cmd.Argument)
		if berr != nil {
			s.err(w, http.StatusBadRequest, berr.Error())
			return
		}
		if err := runner.Cancel(ctx, cmd.Argument); err != nil {
			s.err(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"reply": "Run cancelled."})

	case "show_evidence":
		if cmd.Argument == "" {
			s.err(w, http.StatusBadRequest, "evidence requires a run id")
			return
		}
		nodes, err := s.evidence.Nodes(ctx, cmd.Argument)
		if err != nil {
			s.err(w, http.StatusInternalServerError, err.Error())
			return
		}
		lines := []string{}
		for _, n := range nodes {
			lines = append(lines, n.Type+": "+firstLine(n.Content))
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"reply": joinLines(lines), "count": len(nodes)})

	default:
		s.err(w, http.StatusBadRequest, "unsupported action")
	}
}

func truncTitle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	if len(s) > 140 {
		return s[:140]
	}
	return s
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += "- " + l + "\n"
	}
	return out
}
