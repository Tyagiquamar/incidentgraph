package policy

import (
	"encoding/json"
	"testing"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

func TestReadOnlySelectAllowed(t *testing.T) {
	e := New()
	d := e.Evaluate("query_postgres_readonly", json.RawMessage(`{"sql":"SELECT count(*) FROM incidents"}`))
	if d.Decision != model.PolicyAllowed {
		t.Fatalf("want allowed, got %+v", d)
	}
}

func TestReadOnlyMultipleStatementsDenied(t *testing.T) {
	e := New()
	d := e.Evaluate("query_postgres_readonly", json.RawMessage(`{"sql":"SELECT 1; DROP TABLE users"}`))
	if d.Decision != model.PolicyDenied {
		t.Fatalf("want denied, got %+v", d)
	}
}

func TestReadOnlyDropDenied(t *testing.T) {
	e := New()
	for _, sql := range []string{
		"DROP DATABASE production",
		"DELETE FROM orders",
		"UPDATE users SET admin=true",
		"ALTER TABLE incidents ADD COLUMN x int",
		"INSERT INTO logs VALUES (1)",
		"TRUNCATE audit_log",
	} {
		d := e.Evaluate("query_postgres_readonly", sqlArg(sql))
		if d.Decision != model.PolicyDenied {
			t.Fatalf("%q: want denied, got %+v", sql, d)
		}
	}
}

func TestReadOnlyDangerousFunctionDenied(t *testing.T) {
	e := New()
	for _, sql := range []string{
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_sleep(100)",
		"SELECT * FROM dblink('host=x dbname=y','select 1')",
		"SELECT lo_import('/etc/passwd')",
		"SELECT set_config('search_path','evil',false)",
		"EXPLAIN ANALYZE SELECT 1",
	} {
		d := e.Evaluate("query_postgres_readonly", sqlArg(sql))
		if d.Decision != model.PolicyDenied {
			t.Fatalf("%q: want denied, got %+v", sql, d)
		}
	}
}

func TestCommentsDoNotSmuggleKeywords(t *testing.T) {
	e := New()
	// keyword hidden inside a comment must not make a benign select fail,
	// and a comment cannot rescue a real statement.
	d := e.Evaluate("query_postgres_readonly", sqlArg("SELECT 1 -- DROP TABLE x"))
	if d.Decision != model.PolicyAllowed {
		t.Fatalf("comment-only mention should be ignored, got %+v", d)
	}
}

func TestWriteRequiresApproval(t *testing.T) {
	e := New()
	d := e.Evaluate("restart_service", json.RawMessage(`{"service":"checkout"}`))
	if d.Decision != model.PolicyNeedsApproval || d.Risk != model.RiskWrite {
		t.Fatalf("want needs_approval/write, got %+v", d)
	}
}

func TestPrivilegedForbidden(t *testing.T) {
	e := New()
	for _, tool := range []string{"delete_database", "admin_delete_all_users", "execute_shell", "unknown_tool"} {
		d := e.Evaluate(tool, json.RawMessage(`{}`))
		if d.Decision != model.PolicyDenied || d.Risk != model.RiskPrivilege {
			t.Fatalf("%s: want denied/privileged, got %+v", tool, d)
		}
	}
}

func TestDollarQuotedStringSplitsSafely(t *testing.T) {
	stmts, err := SplitStatements("SELECT '$$;' AS x; SELECT 2")
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) != 2 {
		t.Fatalf("want 2 statements, got %d: %v", len(stmts), stmts)
	}
}

func sqlArg(sql string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"sql": sql})
	return b
}
