package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/runs"
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

// acceptedBackends are the backends this build genuinely implements.
// "native-v2" is intentionally NOT accepted: no separate versioned native
// implementation exists, and advertising one would be dishonest.
var acceptedBackends = map[string]bool{"native-v1": true, "hermes": true}

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
	if !acceptedBackends[backend] {
		s.err(w, http.StatusBadRequest, `unknown backend; supported: native-v1|hermes`)
		return
	}
	// honest selection: never silently run a different engine than asked for
	selected, ok := s.ForBackend(backend)
	if !ok {
		s.err(w, http.StatusServiceUnavailable,
			fmt.Sprintf("backend %q is not configured on this deployment", backend))
		return
	}
	if backend == "hermes" && !s.hermesHealthy(r) {
		s.err(w, http.StatusServiceUnavailable, `hermes backend unreachable; refusing to silently substitute the native engine`)
		return
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
		// The runner acquires its own fenced lease (single ownership path);
		// if a worker claimed the run first this fails cleanly and is logged.
		if err := selected.Start(bg, run.ID); err != nil {
			s.log.Error("run failed", observability.F{"run_id": run.ID, "backend": backend, "error": err.Error()})
		}
	}()
	s.writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) hermesHealthy(r *http.Request) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	h, ok := s.ForBackend("hermes")
	if !ok {
		return false
	}
	if hh, ok := h.(interface {
		Healthy(ctx context.Context) bool
	}); ok {
		return hh.Healthy(ctx)
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
	// Backend-aware dispatch: cancel goes to the engine that owns the run.
	runner, err := s.backendForRun(r.Context(), id)
	if err != nil {
		s.err(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := runner.Cancel(contextDetach(), id); err != nil {
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

// decide persists the human decision ATOMICALLY (DecideApprovalTx): approval
// row + tool call + run transition needs_approval→running in one transaction,
// leaving the run claimable through the normal fenced-lease scheduler. The
// runner that picks it up is resolved by the RUN'S persisted backend.
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
	updated, txErr := s.runs.DecideApprovalTx(r.Context(), id, status, decidedBy)
	if txErr != nil {
		if errors.Is(txErr, runs.ErrApprovalAlreadyDecided) {
			s.err(w, http.StatusConflict, fmt.Sprintf("approval already %s", updated.Status))
			return
		}
		s.err(w, http.StatusInternalServerError, txErr.Error())
		return
	}

	// Trigger an immediate resume attempt; if this process loses the race to
	// a worker, the worker's Resume claims the lease instead. Dispatch is
	// backend-aware: the run's persisted backend decides which runner runs.
	go func() {
		bg := contextDetach()
		runner, berr := s.backendForRun(bg, appr.RunID)
		if berr != nil {
			s.log.Error("resume dispatch failed", observability.F{"run_id": appr.RunID, "error": berr.Error()})
			return
		}
		if err := runner.Resume(bg, appr.RunID); err != nil {
			s.log.Info("resume not taken by api; scheduler will pick it up",
				observability.F{"run_id": appr.RunID, "reason": err.Error()})
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
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering
	flusher.Flush()

	// Resume semantics: ?since=N wins; otherwise honor the standard
	// Last-Event-ID header so EventSource reconnects replay correctly.
	if since == 0 {
		if lei := r.Header.Get("Last-Event-ID"); lei != "" {
			if n := int64(queryIntRaw(lei)); n > 0 {
				since = n
			}
		}
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	heartbeat := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	defer heartbeat.Stop()
	idleDeadline := time.Now().Add(15 * time.Minute)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			// comment frame keeps intermediaries from closing idle streams
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
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

func queryIntRaw(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
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
