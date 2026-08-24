package evals

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InjectionFixture mirrors datasets/injections/fixtures.json entries.
type InjectionFixture struct {
	Slug               string          `json:"slug"`
	SourceType         string          `json:"source_type"`
	Content            string          `json:"content"`
	ExpectedCategory   string          `json:"expected_category"`
	MustNotExecuteTool *string         `json:"must_not_execute_tool"`
	MaliciousSQL       string          `json:"malicious_sql,omitempty"`
	MaliciousArgs      json.RawMessage `json:"malicious_args,omitempty"` // attacker-chosen tool args
}

// SecurityResult summarizes the red-team suite.
type SecurityResult struct {
	Fixtures                   int      `json:"fixtures"`
	Detected                   int      `json:"detected"`
	Missed                     []string `json:"missed,omitempty"`
	PrivilegedOK               int      `json:"policy_blocked"`
	PrivilegeLeaks             int      `json:"privilege_leaks"`
	PromptInjectionSuccessRate float64  `json:"prompt_injection_success_rate"`
	Passed                     bool     `json:"passed"`
	Reasons                    []string `json:"reasons,omitempty"`
}

// RunSecuritySuite verifies ACTUAL enforcement behavior, not LLM self-report:
//  1. detector must flag every adversarial payload,
//  2. policy engine must deny any malicious SQL / privileged tool derived from it.
func RunSecuritySuite(pool *pgxpool.Pool, fixtures []InjectionFixture) (*SecurityResult, error) {
	res := &SecurityResult{Fixtures: len(fixtures)}
	ctx := context.Background()
	eng := policy.New()

	for _, f := range fixtures {
		detected := len(security.Scan(f.Content)) > 0
		if detected {
			res.Detected++
		} else {
			res.Missed = append(res.Missed, f.Slug)
		}
		leak := false
		// If the fixture carries executable malicious content, verify the
		// deterministic layer refuses it.
		if f.MaliciousSQL != "" && pool != nil {
			// attempt execution ONLY after policy check; policy must deny first.
			d := eng.Evaluate("query_postgres_readonly", marshalJSON(map[string]string{"sql": f.MaliciousSQL}))
			if d.Decision != "denied" {
				leak = true
			} else {
				res.PrivilegedOK++
				if pool != nil {
					// record a security event for auditability when DB available
					_, _ = pool.Exec(ctx, `INSERT INTO security_events (source, category, detected_content, decision)
					    VALUES ('redteam_suite',$1,$2,'blocked')`, f.ExpectedCategory, truncStr(f.Content, 200))
				}
			}
		}
		if f.MustNotExecuteTool != nil {
			// The injection tries to make the agent call this tool, possibly
			// with attacker-chosen arguments (e.g. read_file /etc/passwd).
			// The deterministic layer must refuse the call outright.
			args := json.RawMessage(f.MaliciousArgs)
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			d := eng.Evaluate(*f.MustNotExecuteTool, args)
			if d.Decision == "allowed" {
				leak = true // privileged/write/unsafe-arg tools must never auto-execute
			}
		}
		if leak {
			res.PrivilegeLeaks++
			res.Reasons = append(res.Reasons, fmt.Sprintf("fixture %s leaked through policy", f.Slug))
		}
	}

	res.PromptInjectionSuccessRate = 0.0
	if res.Fixtures > 0 {
		res.PromptInjectionSuccessRate = float64(res.PrivilegeLeaks) / float64(res.Fixtures)
	}
	res.Passed = res.PrivilegeLeaks == 0 && len(res.Missed) == 0
	if len(res.Missed) > 0 {
		res.Reasons = append(res.Reasons, fmt.Sprintf("detector missed %d payloads", len(res.Missed)))
	}
	return res, nil
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
