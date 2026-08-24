package hermes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/testdb"
)

// fakeHermes implements the documented Hermes-side contract: start / status /
// stop. It records sessions so tests can assert exactly-once semantics.
type fakeHermes struct {
	srv *httptest.Server

	mu        sync.Mutex
	seq       int
	sessions  map[string]*session // id -> state
	started   int                 // count of POST /start calls
	stopped   []string            // ids passed to stop
	completed map[string]bool     // auto-complete after N polls
	polls     map[string]int
}

type session struct {
	status string
	events []map[string]any
}

func newFakeHermes(t *testing.T, autoComplete bool) *fakeHermes {
	f := &fakeHermes{
		sessions:  map[string]*session{},
		completed: map[string]bool{},
	}
	f.polls = map[string]int{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/runs/start", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.started++
		f.seq++
		id := fmt.Sprintf("sess-%d", f.seq)
		f.sessions[id] = &session{status: "running"}
		if autoComplete {
			f.completed[id] = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"session_id": id, "status": "started"})
	})
	mux.HandleFunc("GET /api/runs/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/")
		f.mu.Lock()
		defer f.mu.Unlock()
		sess := f.sessions[id]
		if sess == nil {
			http.NotFound(w, r)
			return
		}
		f.polls[id]++
		if f.completed[id] && f.polls[id] >= 2 {
			sess.status = "completed"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": sess.status, "events": sess.events})
	})
	mux.HandleFunc("POST /api/runs/", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/stop") {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/stop")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.stopped = append(f.stopped, id)
		if s := f.sessions[id]; s != nil {
			s.status = "cancelled"
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHermes) client() *Client { return NewClient(f.srv.URL) }

func newRunnerForTest(t *testing.T, pool interface {
}) (*Runner, *runs.Store) {
	t.Helper()
	return nil, nil
}

func setupRun(t *testing.T, store *runs.Store) string {
	t.Helper()
	ctx := context.Background()
	incID := model.New()
	_ = store.CreateIncident(ctx, model.Incident{ID: incID, Title: "t-" + incID[:8], Service: "checkout"})
	runID := model.New()
	_ = store.CreateRun(ctx, model.AgentRun{ID: runID, IncidentID: incID,
		AgentBackend: "hermes", Status: model.RunRunning})
	return runID
}

func waitForRunStatus(t *testing.T, store *runs.Store, runID, status string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, err := store.GetRun(context.Background(), runID)
		if err == nil && r.Status == status {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %s never reached %s", runID[:8], status)
}

func TestHermesStartPersistsSessionAndCompletes(t *testing.T) {
	pool := testdb.Open(t)
	store := runs.NewStore(pool)
	fh := newFakeHermes(t, true)
	r := NewRunner(fh.client(), store, "http://mcp:8091/mcp", "mcp-secret",
		[]string{"search_docs"})
	r.LeaseTTL = 10 * time.Second
	runID := setupRun(t, store)

	if err := r.Start(context.Background(), runID); err != nil {
		t.Fatalf("start: %v", err)
	}
	waitForRunStatus(t, store, runID, model.RunComplete)

	backend, sess, err := store.ExternalSession(context.Background(), runID)
	if err != nil || backend != "hermes" || !strings.HasPrefix(sess, "sess-") {
		t.Fatalf("session not persisted correctly: backend=%q sess=%q err=%v", backend, sess, err)
	}
	if fh.started != 1 {
		t.Fatalf("start called %d times, want exactly 1", fh.started)
	}
}

func TestHermesResumeContinuesSameSessionWithoutDuplication(t *testing.T) {
	pool := testdb.Open(t)
	store := runs.NewStore(pool)
	fh := newFakeHermes(t, false) // never completes on its own
	r := NewRunner(fh.client(), store, "http://mcp:8091/mcp", "", []string{"search_docs"})
	r.LeaseTTL = 300 * time.Millisecond // short TTL simulates a crashed driver
	runID := setupRun(t, store)

	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background(), runID) }()
	waitForSession(t, store, runID) // let the session register + poll once

	_, sess, _ := store.ExternalSession(context.Background(), runID)
	if sess == "" {
		t.Fatal("session should be persisted immediately after start")
	}

	// Simulate driver crash: abandon the original driver and let its short
	// lease expire. Resume with a NEW runner (fresh identity) must continue
	// the SAME session — no second start call.
	time.Sleep(500 * time.Millisecond)
	r2 := NewRunner(fh.client(), store, "http://mcp:8091/mcp", "", []string{"search_docs"})
	r2.LeaseTTL = 10 * time.Second
	fh.mu.Lock()
	fh.completed[sess] = true
	fh.mu.Unlock()

	if err := r2.Resume(context.Background(), runID); err != nil {
		t.Fatalf("resume existing session: %v", err)
	}
	waitForRunStatus(t, store, runID, model.RunComplete)
	fh.mu.Lock()
	starts := fh.started
	fh.mu.Unlock()
	if starts != 1 {
		t.Fatalf("resume must not create duplicate sessions; starts=%d", starts)
	}
}

func TestHermesResumeWithoutSessionFailsExplicitly(t *testing.T) {
	pool := testdb.Open(t)
	store := runs.NewStore(pool)
	fh := newFakeHermes(t, false)
	r := NewRunner(fh.client(), store, "", "", nil)
	runID := setupRun(t, store)

	err := r.Resume(context.Background(), runID)
	if err == nil || !strings.Contains(err.Error(), "no persisted session id") {
		t.Fatalf("resume without persisted session must fail explicitly, got %v", err)
	}
	fh.mu.Lock()
	starts := fh.started
	fh.mu.Unlock()
	if starts != 0 {
		t.Fatal("failed resume must not create any session")
	}
}

func TestHermesCancelStopsPersistedSession(t *testing.T) {
	pool := testdb.Open(t)
	store := runs.NewStore(pool)
	fh := newFakeHermes(t, false)
	r := NewRunner(fh.client(), store, "", "", nil)
	runID := setupRun(t, store)

	// Start asynchronously so a session exists.
	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background(), runID) }()
	waitForSession(t, store, runID)
	_, sess, _ := store.ExternalSession(context.Background(), runID)

	if err := r.Cancel(context.Background(), runID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	waitForRunStatus(t, store, runID, model.RunCancelled)

	fh.mu.Lock()
	stopped := append([]string{}, fh.stopped...)
	fh.mu.Unlock()
	if len(stopped) != 1 || stopped[0] != sess {
		t.Fatalf("cancel must stop the PERSISTED session %q, stopped=%v", sess, stopped)
	}
	_ = done
}

func TestHermesCancelRecordsRemoteStopFailure(t *testing.T) {
	pool := testdb.Open(t)
	store := runs.NewStore(pool)
	fh := newFakeHermes(t, false)
	r := NewRunner(fh.client(), store, "", "", nil)
	runID := setupRun(t, store)

	done := make(chan error, 1)
	go func() { done <- r.Start(context.Background(), runID) }()
	waitForSession(t, store, runID)

	// Kill the fake server: remote stop will fail.
	fh.srv.Close()
	if err := r.Cancel(context.Background(), runID); err != nil {
		t.Fatalf("local cancellation must still succeed when remote stop fails: %v", err)
	}
	waitForRunStatus(t, store, runID, model.RunCancelled)
	events, _ := store.EventsSince(context.Background(), runID, 0)
	found := false
	for _, e := range events {
		if e.EventType == "hermes_stop_failed" {
			found = true
		}
	}
	if !found {
		t.Fatal("remote stop failure must be recorded as an inspectable event")
	}
	_ = done
}

func waitForSession(t *testing.T, store *runs.Store, runID string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, sess, err := store.ExternalSession(context.Background(), runID)
		if err == nil && sess != "" {
			return sess
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hermes session never persisted for run %s", runID[:8])
	return ""
}
