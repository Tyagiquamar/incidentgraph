package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/incidentgraph/incidentgraph/internal/testdb"
)

// TestReadOnlyDatabaseRoleRejectsWrites proves DEFENSE IN DEPTH: even when
// the policy checker is bypassed entirely (nil), a query executor bound to a
// restricted SELECT-only database role cannot mutate data — the DATABASE
// refuses, not just our parser.
func TestReadOnlyDatabaseRoleRejectsWrites(t *testing.T) {
	admin := testdb.Open(t)
	ctx := context.Background()

	// Provision a restricted role: CONNECT + SELECT only, read-only by default.
	if _, err := admin.Exec(ctx, `DO $$ BEGIN
	    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='ig_readonly_test') THEN
	        CREATE ROLE ig_readonly_test LOGIN PASSWORD 'ig_readonly_test';
	    END IF;
	END $$`); err != nil {
		t.Fatalf("create role: %v", err)
	}
	for _, stmt := range []string{
		`GRANT CONNECT ON DATABASE "current_database" TO ig_readonly_test`,
		`ALTER ROLE ig_readonly_test SET default_transaction_read_only = on`,
	} {
		if strings.Contains(stmt, "current_database") {
			var dbname string
			if err := admin.QueryRow(ctx, `SELECT current_database()`).Scan(&dbname); err != nil {
				t.Fatal(err)
			}
			stmt = `GRANT CONNECT ON DATABASE "` + dbname + `" TO ig_readonly_test`
		}
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	grants := []string{
		`GRANT USAGE ON SCHEMA public TO ig_readonly_test`,
		`GRANT SELECT ON ALL TABLES IN SCHEMA public TO ig_readonly_test`,
	}
	for _, g := range grants {
		if _, err := admin.Exec(ctx, g); err != nil {
			t.Fatalf("%s: %v", g, err)
		}
	}

	dsn := testdb.DSNForRole(t, "ig_readonly_test", "ig_readonly_test")
	roPool := testdb.ConnectPool(t, dsn)

	exec := NewQueryPostgresReadOnly(pgxAdapter{roPool}, nil /*policy bypassed on purpose*/, QueryLimits{})

	// SELECT succeeds through the restricted role + READ ONLY transaction.
	res, err := exec.Execute(ctx, "run", json.RawMessage(`{"sql":"SELECT 1 AS ok"}`))
	if err != nil {
		t.Fatalf("SELECT via restricted role failed: %v", err)
	}
	if !strings.Contains(res.Text, `"ok":1`) && !strings.Contains(res.Text, `"ok"`) {
		t.Fatalf("unexpected result: %s", res.Text)
	}

	// UPDATE must be refused BY THE DATABASE even though the policy layer was
	// bypassed and we connected as the write-capable table owner's peer.
	_, err = exec.Execute(ctx, "run",
		json.RawMessage(`{"sql":"UPDATE incidents SET title='hacked' WHERE true"}`))
	if err == nil {
		t.Fatal("UPDATE succeeded on read-only executor: defense in depth broken")
	}
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "read-only") && !strings.Contains(lower, "permission") &&
		!strings.Contains(lower, "privilege") {
		t.Fatalf("unexpected rejection reason: %v", err)
	}

	// DDL likewise.
	_, err = exec.Execute(ctx, "run",
		json.RawMessage(`{"sql":"DROP TABLE IF EXISTS incidents"}`))
	if err == nil {
		t.Fatal("DROP succeeded on read-only executor")
	}
}
