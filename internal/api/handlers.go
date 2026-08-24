package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/agent"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
)

func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var in model.Incident
	if err := decodeBody(r, &in); err != nil {
		s.err(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	if in.Title == "" || in.Service == "" {
		s.err(w, http.StatusBadRequest, "title and service are required")
		return
	}
	in.ID = model.New()
	in.Status = "open"
	if in.Severity == "" {
		in.Severity = "sev3"
	}
	if err := s.runs.CreateIncident(r.Context(), in); err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	out, _ := s.runs.GetIncident(r.Context(), in.ID)
	s.writeJSON(w, http.StatusCreated, out)
}

func (s *Server) listIncidents(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	items, err := s.runs.ListIncidents(r.Context(), limit)
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if items == nil {
		items = []model.Incident{}
	}
	s.writeJSON(w, http.StatusOK, items)
}

func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	inc, err := s.runs.GetIncident(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusNotFound, "incident not found")
		return
	}
	runList, _ := s.runs.ListRuns(r.Context(), inc.ID, 20)
	s.writeJSON(w, http.StatusOK, map[string]any{"incident": inc, "runs": runList})
}

// startRun creates an AgentRun and executes it asynchronously.
func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	incidentID := r.PathValue("id")
	if _, err := s.runs.GetIncident(r.Context(), incidentID); err != nil {
		s.err(w, http.StatusNotFound, "incident not found")
		return
	}
	var opts struct {
		Backend string `json:"backend"`
		Model   string `json:"model"`
	}
	if r.ContentLength > 0 {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&opts)
	}
	backend := opts.Backend
	if backend == "" {
		backend = "native-v1"
	}
	if backend != "native-v1" && backend != "native-v2" && backend != "hermes" {
		s.err(w, http.StatusBadRequest, `backend must be one of native-v1|native-v2|hermes`)
		return
	}
	var selected agent.Runner = s.runner
	if backend == "hermes" {
		// honest selection: never silently run a different engine than asked for
		if s.hermes == nil {
			s.err(w, http.StatusServiceUnavailable, `hermes backend not configured (set IG_HERMES_ENABLED=1 and IG_HERMES_URL)`)
			return
		}
		if !s.hermesHealthy(r) {
			s.err(w, http.StatusServiceUnavailable, `hermes backend unreachable; refusing to silently substitute the native engine`)
			return
		}
		selected = s.hermes
	}
	run := model.AgentRun{
		ID:           model.New(),
		IncidentID:   incidentID,
		AgentBackend: backend,
		Model:        opts.Model,
		Status:       model.RunRunning,
		CurrentPhase: "received",
	}
	if err := s.runs.CreateRun(r.Context(), run); err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() {
		bg := contextDetach()
		// lease before driving so a concurrent worker cannot double-drive
		claimed, err := s.runs.ClaimRun(bg, run.ID, 10*time.Minute)
		if err != nil || !claimed {
			s.log.Warn("run not claimed for driving", observability.F{"run_id": run.ID, "error": errString(err)})
			return
		}
		defer func() { _ = s.runs.ReleaseLease(bg, run.ID) }()
		if err := selected.Start(bg, run.ID); err != nil {
			s.log.Error("run failed", observability.F{"run_id": run.ID, "backend": backend, "error": err.Error()})
		}
	}()
	s.writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) hermesHealthy(r *http.Request) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	type healthier interface {
		Healthy(ctx context.Context) bool
	}
	if h, ok := s.hermes.(healthier); ok {
		return h.Healthy(ctx)
	}
	return true // runner without a health probe: selection stays honest via Start-time failure
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	run, err := s.runs.GetRun(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusNotFound, "run not found")
		return
	}
	s.writeJSON(w, http.StatusOK, run)
}

func (s *Server) runSteps(w http.ResponseWriter, r *http.Request) {
	steps, err := s.runs.Steps(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if steps == nil {
		steps = []model.AgentStep{}
	}
	s.writeJSON(w, http.StatusOK, steps)
}

func (s *Server) runToolCalls(w http.ResponseWriter, r *http.Request) {
	calls, err := s.runs.ToolCalls(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if calls == nil {
		calls = []model.ToolCall{}
	}
	s.writeJSON(w, http.StatusOK, calls)
}

func (s *Server) toolCallDetail(w http.ResponseWriter, r *http.Request) {
	tc, err := s.runs.GetToolCall(r.Context(), r.PathValue("callId"))
	if err != nil {
		s.err(w, http.StatusNotFound, "tool call not found")
		return
	}
	events, _ := s.runs.ToolCallTimeline(r.Context(), tc.ID)
	if events == nil {
		events = []model.ToolCallEvent{}
	}
	resp := map[string]any{"tool_call": tc, "events": events}
	if tc.DurableExecutionID != "" && s.durable != nil {
		resp["durable_execution"] = s.durableRef(r, tc)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) runHypotheses(w http.ResponseWriter, r *http.Request) {
	hyps, err := s.evidence.Hypotheses(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if hyps == nil {
		hyps = []model.Hypothesis{}
	}
	s.writeJSON(w, http.StatusOK, hyps)
}

func (s *Server) runEvidence(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.evidence.Nodes(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []model.EvidenceNode{}
	}
	s.writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) runGraph(w http.ResponseWriter, r *http.Request) {
	g, err := s.evidence.Graph(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, g)
}

func (s *Server) runModelUsage(w http.ResponseWriter, r *http.Request) {
	usage, err := s.runs.ModelUsage(r.Context(), r.PathValue("id"))
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	if usage == nil {
		usage = []model.ModelUsage{}
	}
	s.writeJSON(w, http.StatusOK, usage)
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.runs.GetRun(r.Context(), id); err != nil {
		s.err(w, http.StatusNotFound, "run not found")
		return
	}
	if err := s.runner.Cancel(contextDetach(), id); err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "cancelling"})
}

// ---------------------------------------------------------------- approvals

type decisionBody struct {
	DecidedBy string `json:"decided_by"`
}

func (s *Server) approveApproval(w http.ResponseWriter, r *http.Request) { s.decide(w, r, true) }
func (s *Server) rejectApproval(w http.ResponseWriter, r *http.Request)  { s.decide(w, r, false) }

func (s *Server) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	id := r.PathValue("id")
	appr, err := s.runs.GetApproval(r.Context(), id)
	if err != nil || appr == nil {
		s.err(w, http.StatusNotFound, "approval not found")
		return
	}
	if appr.Status != "pending" {
		s.err(w, http.StatusConflict, fmt.Sprintf("approval already %s", appr.Status))
		return
	}
	var body decisionBody
	if r.ContentLength > 0 {
		_ = json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&body)
	}
	decidedBy := body.DecidedBy
	if decidedBy == "" {
		decidedBy = authRoleName(r)
	}
	status := "rejected"
	if approve {
		status = "approved"
	}
	if err := s.runs.DecideApproval(r.Context(), id, status, decidedBy); err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, _ := s.runs.GetApproval(r.Context(), id)

	if !approve {
		if appr.ToolCallID != nil {
			_ = s.runs.CompleteToolCall(r.Context(), *appr.ToolCallID, "denied", "", 0, "rejected by operator")
		}
	} else if appr.ToolCallID != nil {
		_ = s.runs.UpdateToolCallPolicy(r.Context(), *appr.ToolCallID, "allowed", "approved")
	}
	// resume the paused run from persisted state (never from scratch)
	go func() {
		bg := contextDetach()
		if err := s.runner.Resume(bg, appr.RunID); err != nil {
			s.log.Error("resume failed", observability.F{"run_id": appr.RunID, "error": err.Error()})
		}
	}()
	s.writeJSON(w, http.StatusOK, updated)
}

// ---------------------------------------------------------------- events (snapshot + SSE)

func (s *Server) runEvents(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("id")
	run, err := s.runs.GetRun(r.Context(), runID)
	if err != nil {
		s.err(w, http.StatusNotFound, "run not found")
		return
	}
	flusher, wantsSSE := supportsFlush(w)
	since := int64(queryInt(r, "since", 0))

	if !wantsSSE {
		events, err := s.runs.EventsSince(r.Context(), runID, since)
		if err != nil {
			s.err(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"run": run, "events": events})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	idleDeadline := time.Now().Add(15 * time.Minute)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			events, err := s.runs.EventsSince(r.Context(), runID, since)
			if err != nil {
				return
			}
			for _, e := range events {
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.EventType, string(e.Payload))
				since = e.Seq
			}
			if len(events) > 0 {
				idleDeadline = time.Now().Add(15 * time.Minute)
				flusher.Flush()
			}
			fresh, _ := s.runs.GetRun(r.Context(), runID)
			if fresh != nil && terminalStatus(fresh.Status) && len(events) == 0 {
				fmt.Fprintf(w, "event: done\ndata: {}\n\n")
				flusher.Flush()
				return
			}
			if time.Now().After(idleDeadline) {
				return
			}
		}
	}
}

func terminalStatus(status string) bool {
	switch status {
	case model.RunComplete, model.RunFailed, model.RunCancelled:
		return true
	}
	return false
}

func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func queryInt(r *http.Request, key string, def int) int {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return def
	}
	n := 0
	for _, c := range raw {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}
