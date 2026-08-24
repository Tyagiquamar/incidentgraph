package api

import (
	"net/http"
)

// EvalsRunner is the interface to the eval platform (implemented by
// internal/evals.Runner). It is injected so api does not import evals.
type EvalsRunner interface {
	RunSuite(agentBackend string, baselineID string) (any, error)
	ListRuns() (any, error)
}

var evalsRunner EvalsRunner

// SetEvalsRunner wires the eval engine (nil-safe: endpoints degrade).
func SetEvalsRunner(er EvalsRunner) { evalsRunner = er }

func (s *Server) listEvals(w http.ResponseWriter, r *http.Request) {
	if evalsRunner == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"runs": []any{}, "note": "eval runner not configured"})
		return
	}
	out, err := evalsRunner.ListRuns()
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) runEvals(w http.ResponseWriter, r *http.Request) {
	if evalsRunner == nil {
		s.err(w, http.StatusServiceUnavailable, "eval runner not configured")
		return
	}
	var in struct {
		Backend  string `json:"backend"`
		Baseline string `json:"baseline_eval_run_id"`
	}
	if r.ContentLength > 0 {
		_ = decodeBody(r, &in)
	}
	if in.Backend == "" {
		in.Backend = "native-v1"
	}
	out, err := evalsRunner.RunSuite(in.Backend, in.Baseline)
	if err != nil {
		s.err(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}
