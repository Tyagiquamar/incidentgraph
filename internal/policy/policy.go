// Package policy implements deterministic tool authorization OUTSIDE the LLM.
//
// The model can propose a tool call; only this engine decides whether it runs.
// READ_ONLY tools execute automatically. WRITE tools require human approval.
// PRIVILEGED tools are forbidden outright.
package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

// Decision is the outcome of evaluating one proposed tool call.
type Decision struct {
	Decision model.PolicyDecision `json:"decision"`
	Risk     model.RiskLevel      `json:"risk"`
	Reason   string               `json:"reason"`
}

// Engine evaluates proposed tool calls deterministically.
type Engine struct {
	risk map[string]model.RiskLevel
}

// New builds an Engine with the default risk table.
func New() *Engine {
	return &Engine{risk: DefaultRiskTable()}
}

// DefaultRiskTable maps tool names to risk levels. Unknown tools are
// PRIVILEGED by default (deny by default).
func DefaultRiskTable() map[string]model.RiskLevel {
	return map[string]model.RiskLevel{
		"search_docs":             model.RiskReadOnly,
		"search_logs":             model.RiskReadOnly,
		"get_deployment":          model.RiskReadOnly,
		"get_git_diff":            model.RiskReadOnly,
		"read_file":               model.RiskReadOnly,
		"search_code":             model.RiskReadOnly,
		"query_metrics":           model.RiskReadOnly,
		"query_postgres_readonly": model.RiskReadOnly,
		"restart_service":         model.RiskWrite,
		"rollback_deployment":     model.RiskWrite,
		"update_config":           model.RiskWrite,
		"delete_database":         model.RiskPrivilege,
		"drop_table":              model.RiskPrivilege,
		"admin_delete_all_users":  model.RiskPrivilege,
		"execute_shell":           model.RiskPrivilege,
		"send_environment":        model.RiskPrivilege,
	}
}

// RiskOf returns the registered risk level for a tool (unknown => privileged).
func (e *Engine) RiskOf(tool string) model.RiskLevel {
	if r, ok := e.risk[tool]; ok {
		return r
	}
	return model.RiskPrivilege
}

// Register adds or overrides the risk level for a tool (used by tests and MCP allowlists).
func (e *Engine) Register(tool string, risk model.RiskLevel) { e.risk[tool] = risk }

// Evaluate inspects the proposed call. args must already be redacted of secrets
// by the caller before persistence; evaluation itself is content-aware for SQL.
func (e *Engine) Evaluate(tool string, args json.RawMessage) Decision {
	risk := e.RiskOf(tool)
	switch risk {
	case model.RiskPrivilege:
		return Decision{Decision: model.PolicyDenied, Risk: risk,
			Reason: fmt.Sprintf("tool %q is privileged; privileged tools are forbidden", tool)}
	case model.RiskWrite:
		return Decision{Decision: model.PolicyNeedsApproval, Risk: risk,
			Reason: fmt.Sprintf("tool %q is write-risk; human approval required", tool)}
	case model.RiskReadOnly:
		if tool == "query_postgres_readonly" {
			if d := checkSQLReadOnly(args); d != nil {
				return *d
			}
		}
		if tool == "read_file" {
			if d := checkReadFilePath(args); d != nil {
				return *d
			}
		}
		return Decision{Decision: model.PolicyAllowed, Risk: risk,
			Reason: "read-only tool auto-approved"}
	default:
		return Decision{Decision: model.PolicyDenied, Risk: model.RiskPrivilege,
			Reason: "unknown risk classification"}
	}
}

// ---------------------------------------------------------------- read_file path guard

// sensitivePathRe matches credential stores, key material and OS files that a
// read-only investigation tool must never open — even when an injected
// document asks the agent to "print /etc/passwd".
var sensitivePathRe = regexp.MustCompile(`(?i)(^|/)(\.ssh|\.aws|\.env)(/|$)|id_rsa|id_ed25519|\.pem$|/etc/(passwd|shadow|sudoers|hosts)|credential|secret|token`)

// checkReadFilePath validates the `path` argument of read_file at the
// deterministic policy layer. Injection defense must not depend on the model.
func checkReadFilePath(args json.RawMessage) *Decision {
	var a struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(args, &a); err != nil || strings.TrimSpace(a.Path) == "" {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "read_file requires a non-empty \"path\" string argument"}
	}
	p := a.Path
	if strings.Contains(p, "\x00") || strings.HasPrefix(p, "/proc/self") {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "path targets process memory or is malformed"}
	}
	if sensitivePathRe.MatchString(p) {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: fmt.Sprintf("path %q matches deny-listed sensitive locations", truncForPolicy(p))}
	}
	return nil
}

func truncForPolicy(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// ---------------------------------------------------------------- SQL guard

var sqlForbiddenKeywords = []string{
	"DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE", "TRUNCATE",
	"GRANT", "REVOKE", "COPY", "VACUUM", "ANALYZE", "REINDEX", "CLUSTER",
	"CALL", "DO", "LISTEN", "NOTIFY", "SET", "RESET", "BEGIN", "COMMIT",
	"ROLLBACK", "SAVEPOINT", "PREPARE", "EXECUTE", "MERGE", "COMMENT",
	"LOCK", "SECURITY", "IMPORT",
}

// dangerous functions that read files, escalate, or enable side channels even
// from within a SELECT.
var sqlForbiddenFunctions = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_sleep",
	"pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf",
	"lo_import", "lo_export", "dblink", "postgres_fdw", "file_fdw",
	"pg_logical_slot_get_changes", "pg_create_logical_replication_slot",
	"set_config", "current_setting", "pg_advisory_lock", "pg_advisory_xact_lock",
}

var allowedLeading = map[string]bool{
	"SELECT": true, "WITH": true, "EXPLAIN": true, "SHOW": true,
}

// checkSQLReadOnly validates the `sql` argument of query_postgres_readonly.
// Rules: exactly one statement; leading keyword SELECT/WITH/EXPLAIN/SHOW;
// no DML/DDL keywords anywhere; no dangerous function calls; no data-writing
// keywords smuggled via comments are impossible because comments are stripped.
func checkSQLReadOnly(args json.RawMessage) *Decision {
	var a struct {
		SQL string `json:"sql"`
	}
	if err := json.Unmarshal(args, &a); err != nil || strings.TrimSpace(a.SQL) == "" {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "query_postgres_readonly requires a non-empty \"sql\" string argument"}
	}
	stmts, err := SplitStatements(a.SQL)
	if err != nil || len(stmts) == 0 {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "could not parse statement safely"}
	}
	if len(stmts) > 1 {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: fmt.Sprintf("multiple statements (%d) not permitted in read-only path", len(stmts))}
	}
	tokens := tokenize(stripComments(stmts[0]))
	up := make([]string, len(tokens))
	for i, t := range tokens {
		up[i] = strings.ToUpper(t)
	}
	if len(up) == 0 {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "empty statement"}
	}
	lead := up[0]
	if lead == "EXPLAIN" && len(up) > 1 && up[1] == "ANALYZE" {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: "EXPLAIN ANALYZE executes the statement and is not read-only"}
	}
	if !allowedLeading[lead] {
		return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
			Reason: fmt.Sprintf("statement type %q is not permitted in read-only path", lead)}
	}
	for _, kw := range sqlForbiddenKeywords {
		for _, t := range up {
			if t == kw {
				return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
					Reason: fmt.Sprintf("keyword %s is forbidden in read-only SQL", kw)}
			}
		}
	}
	lowerTokens := make([]string, len(tokens))
	for i, t := range tokens {
		lowerTokens[i] = strings.ToLower(t)
	}
	for _, fn := range sqlForbiddenFunctions {
		for _, t := range lowerTokens {
			if t == fn {
				return &Decision{Decision: model.PolicyDenied, Risk: model.RiskReadOnly,
					Reason: fmt.Sprintf("function %s is forbidden in read-only SQL", fn)}
			}
		}
	}
	return nil
}

// stripComments removes -- line comments and /* block */ comments.
func stripComments(sql string) string {
	var b strings.Builder
	inLine, inBlock, inSingle, inDouble := false, false, false, false
	i := 0
	for i < len(sql) {
		c := sql[i]
		next := byte(0)
		if i+1 < len(sql) {
			next = sql[i+1]
		}
		switch {
		case inLine:
			if c == '\n' {
				inLine = false
				b.WriteByte(c)
			}
		case inBlock:
			if c == '*' && next == '/' {
				inBlock = false
				i++
			}
		case inSingle:
			b.WriteByte(c)
			if c == '\'' {
				if next == '\'' {
					b.WriteByte(next)
					i++
				} else {
					inSingle = false
				}
			}
		case inDouble:
			b.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
		default:
			switch {
			case c == '-' && next == '-':
				inLine = true
				i++
			case c == '/' && next == '*':
				inBlock = true
				i++
			case c == '\'':
				inSingle = true
				b.WriteByte(c)
			case c == '"':
				inDouble = true
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		}
		i++
	}
	return b.String()
}

// SplitStatements splits on top-level semicolons outside quotes/dollar quotes.
func SplitStatements(sql string) ([]string, error) {
	var stmts []string
	var cur strings.Builder
	var dollarTag string
	inSingle, inDouble := false, false
	i := 0
	for i < len(sql) {
		c := sql[i]
		switch {
		case inSingle:
			cur.WriteByte(c)
			if c == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' {
					cur.WriteByte('\'')
					i++
				} else {
					inSingle = false
				}
			}
		case inDouble:
			cur.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
		case dollarTag != "":
			if sql[i] == '$' {
				end := strings.IndexByte(sql[i+1:], '$')
				tag := "$"
				ok := end >= 0
				if ok {
					tag = sql[i : i+2+end]
				}
				if tag == dollarTag {
					cur.WriteString(tag)
					i += len(tag) - 1
					dollarTag = ""
					break
				}
			}
			cur.WriteByte(c)
		case c == '\'':
			inSingle = true
			cur.WriteByte(c)
		case c == '"':
			inDouble = true
			cur.WriteByte(c)
		case c == '$':
			rest := sql[i:]
			m := dollarTagRe.FindString(rest)
			if m != "" {
				dollarTag = m
				cur.WriteString(m)
				i += len(m) - 1
			} else {
				cur.WriteByte(c)
			}
		case c == ';':
			s := strings.TrimSpace(cur.String())
			if s != "" {
				stmts = append(stmts, s)
			}
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
		i++
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts, nil
}

func tokenize(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' ||
			r == '(' || r == ')' || r == ',' || r == ';' ||
			r == '=' || r == '<' || r == '>' || r == '+' || r == '-' ||
			r == '*' || r == '/' || r == '.' || r == '!' || r == '|'
	})
	out := fields[:0]
	for _, f := range fields {
		f = strings.Trim(f, "`'\"")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
