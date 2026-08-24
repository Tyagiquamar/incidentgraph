// Package security implements prompt-injection detection, secret redaction,
// and the security-event recorder.
//
// Core principle: retrieved content is DATA, never instructions. Only
// SYSTEM_TRUSTED context carries instruction authority.
package security

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

// Finding is one detected adversarial pattern inside untrusted content.
type Finding struct {
	Category string `json:"category"` // security_events.category enum
	Snippet  string `json:"snippet"`
	Severity string `json:"severity"` // low|medium|high|critical
}

var injectionPatterns = []struct {
	category string
	severity string
	re       *regexp.Regexp
}{
	// direct prompt injection
	{"prompt_injection", "critical", regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)`)},
	{"prompt_injection", "critical", regexp.MustCompile(`(?i)disregard\s+(all\s+)?(your|the|any)\s+(instructions|rules|policies)`)},
	{"prompt_injection", "high", regexp.MustCompile(`(?i)(you\s+are\s+now|new\s+instructions?:|act\s+as\s+(if\s+)?(a|an)\s+(unrestricted|unfiltered))`)},
	{"prompt_injection", "high", regexp.MustCompile(`(?i)forget\s+(everything|all)\s+(you|that\s+was)`)},
	{"instruction_conflict", "high", regexp.MustCompile(`(?i)override\s+(your\s+|the\s+)?(system\s+|security\s+)?(instructions|policies|policy|rules|prompt)`)},

	// fake authority / fake approval
	{"fake_approval", "critical", regexp.MustCompile(`(?i)(pre-?approved|approval\s+(granted|already\s+given)|approved\s+by\s+(admin|system)|this\s+action\s+is\s+authorized)`)},
	{"fake_approval", "critical", regexp.MustCompile(`(?i)(skip|bypass)\s+(the\s+)?(human\s+)?approval(\s+(workflow|step))?`)},
	{"prompt_injection", "high", regexp.MustCompile(`(?i)^SYSTEM:\s`)},
	{"prompt_injection", "high", regexp.MustCompile(`(?i)ADMIN\s+NOTE:`)},

	// credential exfiltration
	{"credential_exfil", "critical", regexp.MustCompile(`(?i)(reveal|print|show|send|exfiltrat\w*|leak)[^.]{0,40}(environment\s+variables?|env\b|\bsecrets?\b|api[ -]?keys?|credentials?)`)},
	{"credential_exfil", "critical", regexp.MustCompile(`(?i)(curl|wget|fetch|POST\s+to|webhook)[^.]{0,60}(attacker|evil|exfil|[a-z0-9.-]+\.example|webhook\.site)`)},
	{"credential_exfil", "high", regexp.MustCompile(`(?i)send\s+(them\s+)?(externally|to\s+me|home)`)},

	// destructive SQL
	{"sql_destructive", "critical", regexp.MustCompile(`(?i)\b(DROP\s+(DATABASE|TABLE|SCHEMA)|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+|UPDATE\s+\w+\s+SET\s+[^;]*(;|$))`)},
	// dangerous SQL functions: file reads, privilege escalation, exfil channels
	{"sql_destructive", "critical", regexp.MustCompile(`(?i)\b(pg_read_file|pg_read_binary_file|pg_ls_dir|pg_sleep|dblink|lo_import|lo_export|copy\s+[^\n]{0,40}\s+program)\b`)},

	// destructive shell
	{"destructive_shell", "critical", regexp.MustCompile(`(?i)(rm\s+-rf\s+/|mkfs(\.\w+)?\s|dd\s+if=/dev/zero|shutdown\s+(-h|-r)?\s+now|:\(\)\s*\{.*\}\s*;:)`)},
	{"destructive_shell", "high", regexp.MustCompile(`(?i)(chmod\s+777\s+/etc|>\s*/dev/sd[a-z]|curl[^|]*\|\s*(ba)?sh)`)},

	// tool loop bait / data poisoning
	{"loop_bait", "high", regexp.MustCompile(`(?i)(call|run|invoke)\s+(this\s+)?(tool|command|function)\s+(forever|in\s+a\s+loop|repeatedly|100\s+times)`)},
	{"data_poisoning", "high", regexp.MustCompile(`(?i)(root\s+cause\s+is|conclusion:)[^.]{0,80}(ignore|skip|do\s+not\s+investigate|false)`)},
	{"data_poisoning", "medium", regexp.MustCompile(`(?i)this\s+document\s+(supersedes|overrides)\s+(all\s+)?other\s+(evidence|documents|sources)`)},

	// tool output asking for privileged calls
	{"prompt_injection", "critical", regexp.MustCompile(`(?i)(please\s+)?call\s+(admin_delete_all_users|delete_database|execute_shell|drop_table)`)},
	{"prompt_injection", "high", regexp.MustCompile(`(?i)run\s+(curl\s+attacker|the\s+cleanup\s+script\s+from)`)},
}

var base64BlobRe = regexp.MustCompile(`(?:[A-Za-z0-9+/=]{24,})`)
var encodedTriggerRe = regexp.MustCompile(`(?i)(encoded|base64)`)

// Scan inspects content from an untrusted source and returns findings.
func Scan(content string) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(f Finding) {
		if !seen[f.Category] {
			out = append(out, f)
			seen[f.Category] = true
		}
	}
	for _, p := range injectionPatterns {
		if m := p.re.FindString(content); m != "" {
			add(Finding{Category: p.category, Snippet: truncate(m, 200), Severity: p.severity})
		}
	}
	if f := scanEncoded(content); f != nil {
		add(*f)
	}
	if f := scanMalformedJSON(content); f != nil {
		add(*f)
	}
	return out
}

// scanMalformedJSON flags tool output that claims to be a JSON object but
// does not parse — a classic poisoning/parse-confusion vector. Enumerated
// text renders like "[1] path…" and must NOT be treated as JSON; only content
// starting with '{' is checked. Flagged content stays available as evidence
// but is treated as untrusted.
func scanMalformedJSON(content string) *Finding {
	t := strings.TrimSpace(content)
	if !strings.HasPrefix(t, "{") {
		return nil
	}
	if json.Valid([]byte(t)) {
		return nil
	}
	return &Finding{Category: "malformed_tool_output", Snippet: truncate(t, 80), Severity: "medium"}
}

// scanEncoded detects base64-encoded adversarial instructions near encoding hints,
// or any long base64 blob that decodes to known injection text.
func scanEncoded(content string) *Finding {
	for _, m := range base64BlobRe.FindAllString(content, 20) {
		raw, err := base64.StdEncoding.DecodeString(m)
		if err != nil || len(raw) < 12 {
			continue
		}
		text := strings.ToLower(string(raw))
		if strings.Contains(text, "ignore") || strings.Contains(text, "instructions") ||
			strings.Contains(text, "drop database") || strings.Contains(text, "password") ||
			strings.Contains(text, "rm -rf") {
			return &Finding{Category: "encoded_instruction", Snippet: fmt.Sprintf("%s => %q", truncate(m, 48), truncate(string(raw), 120)), Severity: "critical"}
		}
	}
	if encodedTriggerRe.MatchString(content) {
		return &Finding{Category: "encoded_instruction", Snippet: "encoding hint present; decoded payload inspected", Severity: "low"}
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AuthorityOf states whether a trust level may carry instructions.
func AuthorityOf(t model.TrustLevel) bool { return t == model.TrustSystemTrusted }

// ---------------------------------------------------------------- redaction

var (
	bearerRe     = regexp.MustCompile(`(?i)(authorization["':=\s]+bearer\s+)[A-Za-z0-9._~+/=-]+`)
	apiKeyHdrRe  = regexp.MustCompile(`(?i)(x-api-key["':=\s]+|api[_-]?key["':=\s]+)[A-Za-z0-9._~+/=-]{8,}`)
	openAIKeyRe  = regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`)
	githubTokRe  = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{16,}`)
	awsKeyRe     = regexp.MustCompile(`AKIA[A-Z0-9]{12,}`)
	jwtRe        = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	connStrRe    = regexp.MustCompile(`(?i)(postgres(ql)?|mysql|mongodb(\+srv)?)://([^:/\s"@]+):([^@/\s"]+)@`)
	kvSecretRe   = regexp.MustCompile(`(?im)^([A-Z0-9_]*(PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)[A-Z0-9_]*)\s*[=:]\s*(\S{4,})$`)
	privateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)
)

const redactedPlaceholder = "[REDACTED]"

// Redact scrubs secrets from arbitrary text so it can be persisted or shown.
func Redact(s string) string {
	out := bearerRe.ReplaceAllString(s, `${1}`+redactedPlaceholder)
	out = apiKeyHdrRe.ReplaceAllString(out, `${1}`+redactedPlaceholder)
	out = openAIKeyRe.ReplaceAllString(out, redactedPlaceholder)
	out = githubTokRe.ReplaceAllString(out, redactedPlaceholder)
	out = awsKeyRe.ReplaceAllString(out, redactedPlaceholder)
	out = jwtRe.ReplaceAllString(out, redactedPlaceholder)
	out = connStrRe.ReplaceAllString(out, `$1://$4:`+redactedPlaceholder+`@`)
	out = privateKeyRe.ReplaceAllString(out, redactedPlaceholder)
	out = kvSecretRe.ReplaceAllString(out, `$1=`+redactedPlaceholder)
	return out
}

// RedactJSON applies Redact to every string leaf of a JSON value.
func RedactJSON(raw []byte) []byte {
	var v any
	if err := parseJSON(raw, &v); err != nil {
		return []byte(Redact(string(raw)))
	}
	redacted := redactValue(v)
	out, err := marshalJSON(redacted)
	if err != nil {
		return []byte(redactedPlaceholder)
	}
	return out
}
