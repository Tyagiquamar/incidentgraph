package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/tools"
)

func testDeps(auth bool) Deps {
	eng := policy.New()
	reg := tools.NewRegistry(tools.NewSearchDocs(nil, nil), tools.NewRestartService())
	return Deps{
		Tools:       reg,
		Policy:      eng,
		AuthEnabled: auth,
		AuthToken:   "secret-token",
		Allowlist:   map[string]bool{"search_docs": true},
	}
}

func post(h http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	if ct := "application/json"; ct != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMCPAuthEnforcement(t *testing.T) {
	h, err := Handler(testDeps(true))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"no auth rejected", "", http.StatusUnauthorized},
		{"wrong token rejected", "wrong-token", http.StatusUnauthorized},
		{"valid token allowed", "secret-token", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(h, tc.token, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// Health endpoint stays unauthenticated.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", rec.Code)
	}
}

func TestMCPAllowlistDeniesWriteTools(t *testing.T) {
	h, _ := Handler(testDeps(false))
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"restart_service","arguments":{"service":"x"}}}`
	rec := post(h, "", body)
	if !strings.Contains(rec.Body.String(), "not allowlisted") {
		t.Fatalf("write tool must be denied by allowlist: %s", rec.Body.String())
	}
}

func TestMCPRejectsBadRequests(t *testing.T) {
	h, _ := Handler(testDeps(false))

	// malformed JSON
	rec := post(h, "", `{broken`)
	if rec.Code != http.StatusOK { // JSON-RPC errors ride on HTTP 200
		t.Fatalf("http status = %d", rec.Code)
	}
	var resp struct {
		Error *struct{ Code int } `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != CodeParseError {
		t.Fatalf("want parse error, got %s", rec.Body.String())
	}

	// wrong content type
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "text/plain")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest && !strings.Contains(rec2.Body.String(), "Content-Type") {
		t.Fatalf("content-type guard failed: %d %s", rec2.Code, rec2.Body.String())
	}

	// unknown method
	rec3 := post(h, "", `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	if !strings.Contains(rec3.Body.String(), "method not found") {
		t.Fatalf("unknown method handling wrong: %s", rec3.Body.String())
	}

	// tools/call without name
	rec4 := post(h, "", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}`)
	if !strings.Contains(rec4.Body.String(), "params.name is required") {
		t.Fatalf("missing name handling wrong: %s", rec4.Body.String())
	}
}

func TestMCPHandlerValidatesDeps(t *testing.T) {
	d := testDeps(false)
	d.Allowlist = map[string]bool{"restart_service": true} // WRITE tool must be refused
	if _, err := Handler(d); err == nil || !strings.Contains(err.Error(), "must never be exposed") {
		t.Fatalf("write-tool allowlist must fail construction, got %v", err)
	}
	d2 := testDeps(false)
	d2.Allowlist = map[string]bool{"nonexistent": true}
	if _, err := Handler(d2); err == nil {
		t.Fatal("allowlist referencing missing tool must fail construction")
	}
}

var _ = context.Background
var _ = bytes.MinRead
