package llm

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"
)

func timeNow() time.Time                  { return time.Now() }
func timeSince(t time.Time) time.Duration { return time.Since(t) }

// MockProvider is a fully deterministic, offline model implementation.
//
// Purpose: CI, tests and portfolio demos run WITHOUT paid APIs. The mock
// implements a small rule-based investigator over the structured prompt
// contract used by NativeAgentRunner (TASK/EVIDENCE/HYPOTHESES blocks).
// It is clearly labeled as `mock` everywhere usage is recorded — metrics
// produced with it are real measurements of THIS system, not claims about
// frontier-model performance.
type MockProvider struct {
	Model string // mock-small | mock-large
}

func NewMock(model string) *MockProvider {
	if model == "" {
		model = "mock-small"
	}
	return &MockProvider{Model: model}
}

func (m *MockProvider) Name() string { return "mock" }

var taskRe = regexp.MustCompile(`(?m)^TASK:\s*(\w+)`)
var evidenceHeaderRe = regexp.MustCompile(`^-\s*\[([A-Za-z]+-[A-Za-z0-9]+)\]\s*type=(\w+)\s+source=(\S*)\s+trust=(\w+)\s*$`)

type evItem struct {
	ID     string
	Type   string
	Source string
	Trust  string
	Body   string
}

// parseEvidence walks the EVIDENCE block line by line (RE2 has no lookahead).
func parseEvidence(prompt string) []evItem {
	var out []evItem
	var cur *evItem
	var body strings.Builder
	flush := func() {
		if cur != nil {
			cur.Body = strings.TrimSpace(body.String())
			out = append(out, *cur)
			cur, body = nil, strings.Builder{}
		}
	}
	for _, ln := range strings.Split(prompt, "\n") {
		if m := evidenceHeaderRe.FindStringSubmatch(strings.TrimRight(ln, "\r")); m != nil {
			flush()
			cur = &evItem{ID: m[1], Type: m[2], Source: m[3], Trust: m[4]}
			continue
		}
		if cur != nil {
			body.WriteString(ln)
			body.WriteString("\n")
		}
	}
	flush()
	return out
}

func (m *MockProvider) Generate(ctx context.Context, req GenRequest) (*GenResponse, error) {
	start := timeNow()
	prompt := req.System
	for _, msg := range req.Messages {
		prompt += "\n" + msg.Content
	}
	task := ""
	if mt := taskRe.FindStringSubmatch(prompt); mt != nil {
		task = strings.ToLower(mt[1])
	}
	var out string
	switch task {
	case "plan":
		out = mockPlan(prompt)
	case "hypotheses":
		out = mockHypotheses(prompt)
	case "verify":
		out = mockVerify(prompt)
	case "report":
		out = mockReport(prompt)
	case "judge":
		out = `{"scores":{"root_cause_quality":3,"evidence_grounding":4,"completeness":3,"actionability":3},"rationale":"mock judge"}`
	default:
		out = `{"ok":true}`
	}
	inTok := estimateTokens(req.System) + estimateTokens(concatMessages(req.Messages))
	outTok := estimateTokens(out)
	return &GenResponse{
		Text: out, InputTokens: inTok, OutputTokens: outTok,
		LatencyMS: int64(timeSince(start).Milliseconds()),
		Model:     m.Model, Provider: m.Name(), FinishReason: "stop",
	}, nil
}

// ---------------------------------------------------------------- evidence parsing

// failure signature table: ordered by specificity.
var signatures = []struct {
	category  string
	statement string
	keywords  []string
}{
	{"db_pool_regression",
		"Database connection pool regression caused elevated checkout latency after deployment %COMMIT%.",
		[]string{"pool_size", "pool exhausted", "connection pool", "acquire timeout", "db wait"}},
	{"n_plus_one_query",
		"N+1 query pattern: per-item SELECTs multiplied endpoint latency with item count.",
		[]string{"n+1", "repeated select", "select ... from order_items", "queries per item", "1 query per"}},
	{"cache_stampede",
		"Cache expiration synchronized across keys causing a stampede on the backing store.",
		[]string{"cache miss", "stampede", "thundering herd", "ttl expired", "redis evict"}},
	{"downstream_timeout",
		"A downstream dependency's increased latency propagated timeouts upstream.",
		[]string{"upstream timeout", "downstream latency", "context deadline", "circuit open"}},
	{"bad_deploy_config",
		"A configuration regression introduced by the deployment caused the incident.",
		[]string{"config changed", "env var changed", "misconfigured", "feature flag flipped", "worker_count"}},
	{"connection_leak",
		"Connections are leaked per request until exhaustion.",
		[]string{"leak", "connections not closed", "defer close missing", "idle in transaction"}},
	{"queue_backlog",
		"Consumer throughput fell below producer rate creating an unbounded queue backlog.",
		[]string{"backlog", "lag", "consumer group", "unacked"}},
	{"disk_saturation",
		"Disk utilization saturated causing IO wait spikes across services.",
		[]string{"disk usage", "iowait", "inode", "partition full"}},
	{"rate_limit",
		"A third-party rate limit was hit after traffic growth.",
		[]string{"429", "rate limit", "quota exceeded"}},
	{"deadlock",
		"Lock contention escalated into database deadlocks.",
		[]string{"deadlock detected", "lock wait", "serialization failure"}},
	{"dns_issue",
		"DNS resolution failures or stale records caused connection errors.",
		[]string{"nxdomain", "dns", "resolution failed", "stale record"}},
	{"expired_secret",
		"An expired credential/secret caused authentication failures.",
		[]string{"token expired", "secret expired", "401 unauthorized", "credential expired"}},
	{"broken_feature_flag",
		"A feature flag rollout enabled a defective code path.",
		[]string{"feature flag", "flag enabled", "rollout percentage"}},
	{"retry_policy",
		"Aggressive retries amplified load (retry storm).",
		[]string{"retry storm", "retries exceeded", "max retry", "backoff disabled"}},
}

func matchSignatures(text string) []int {
	lower := strings.ToLower(text)
	var hits []int
	for i, sig := range signatures {
		for _, kw := range sig.keywords {
			if strings.Contains(lower, kw) {
				hits = append(hits, i)
				break
			}
		}
	}
	return hits
}

func findCommit(prompt string) string {
	re := regexp.MustCompile(`commit[: ]+([a-f0-9]{6,10})`)
	if m := re.FindStringSubmatch(prompt); m != nil {
		return m[1]
	}
	re2 := regexp.MustCompile(`(deployments|commits)/[\w-]+/([a-zA-Z0-9._-]+)`)
	if m := re2.FindStringSubmatch(prompt); m != nil {
		return m[2]
	}
	return "recent-deploy"
}

// ---------------------------------------------------------------- mock tasks

func mockPlan(prompt string) string {
	hits := matchSignatures(prompt)
	tools := []string{"search_docs", "search_logs", "query_metrics"}
	text := strings.ToLower(prompt)
	add := func(ts ...string) {
		for _, t := range ts {
			found := false
			for _, existing := range tools {
				if existing == t {
					found = true
					break
				}
			}
			if !found {
				tools = append(tools, t)
			}
		}
	}
	if strings.Contains(text, "deploy") || strings.Contains(text, "after release") || len(hits) > 0 {
		add("get_deployment", "get_git_diff")
	}
	if strings.Contains(text, "latency") || strings.Contains(text, "slow") || strings.Contains(text, "database") || strings.Contains(text, "db") {
		add("query_metrics")
	}
	if strings.Contains(text, "sql") || strings.Contains(text, "rows") || strings.Contains(text, "table") {
		add("query_postgres_readonly")
	}
	if strings.Contains(text, "code") || strings.Contains(text, "function") {
		add("search_code")
	}
	// WRITE-risk remediation is proposed ONLY on an explicit operator request
	// in the incident text; it then requires human approval via policy.
	if strings.Contains(text, "remediate") || strings.Contains(text, "remediation approved") {
		add("restart_service")
	}
	sort.Strings(tools)
	plan := map[string]any{
		"objectives": []string{
			"Identify the most probable root cause of the reported symptoms",
			"Gather corroborating and contradicting evidence from deployments, logs and metrics",
			"Produce an auditable report with cited evidence",
		},
		"tools_needed":        tools,
		"risks":               []string{"read-only investigation; write actions require human approval"},
		"completion_criteria": []string{"at least one verified hypothesis with supporting evidence", "report cites evidence IDs"},
	}
	b, _ := json.Marshal(plan)
	return string(b)
}

func mockHypotheses(prompt string) string {
	evidence := parseEvidence(prompt)
	allText := prompt
	for _, e := range evidence {
		allText += "\n" + e.Body
	}
	hits := matchSignatures(allText)
	if len(hits) == 0 {
		// honest abstention when nothing matches
		return `{"hypotheses":[{"claim":"Root cause cannot be established with current evidence.","supporting_evidence_ids":[],"contradicting_evidence_ids":[],"confidence":0.2,"root_cause_category":"insufficient_evidence"}]}`
	}
	type hyp struct {
		Claim      string   `json:"claim"`
		Supporting []string `json:"supporting_evidence_ids"`
		Contradict []string `json:"contradicting_evidence_ids"`
		Confidence float64  `json:"confidence"`
		Category   string   `json:"root_cause_category"`
	}
	var out []hyp
	for rank, hi := range hits {
		if rank >= 3 {
			break
		}
		sig := signatures[hi]
		stmt := strings.ReplaceAll(sig.statement, "%COMMIT%", findCommit(prompt))
		lowerStmt := strings.ToLower(sig.category + " " + strings.Join(sig.keywords, " "))
		var support, contra []string
		for _, e := range evidence {
			body := strings.ToLower(e.Body)
			scored := false
			for _, kw := range sig.keywords {
				if strings.Contains(body, kw) {
					scored = true
					break
				}
			}
			if scored && !strings.Contains(body, "remained stable") && !strings.Contains(body, "no anomalies") {
				support = append(support, e.ID)
				continue
			}
			// evidence that is about a different subsystem supports ranking alternatives
			if containsAny(lowerStmt, []string{"redis"}) && strings.Contains(body, "redis") ||
				containsAny(lowerStmt, []string{"cache"}) && strings.Contains(body, "redis") {
				support = append(support, e.ID)
				continue
			}
			if strings.Contains(body, "stable") || strings.Contains(body, "normal") {
				contra = append(contra, e.ID)
			}
		}
		// corroboration rule: a single weakly-matching chunk is not enough to
		// assert a root cause. Without at least two supporting items the honest
		// answer is explicit abstention (spec: insufficient-evidence scenario).
		if len(support) < 2 {
			continue
		}
		conf := 0.35 + 0.15*float64(len(support)) - 0.1*float64(len(contra))
		if conf > 0.95 {
			conf = 0.95
		}
		if conf < 0.05 {
			conf = 0.05
		}
		out = append(out, hyp{Claim: stmt, Supporting: support, Contradict: contra, Confidence: round2(conf), Category: sig.category})
	}
	b, _ := json.Marshal(map[string]any{"hypotheses": out})
	return string(b)
}

func mockVerify(prompt string) string {
	// Verification re-ranks: hypotheses whose supporting evidence appears again
	// in VERIFICATION_EVIDENCE keep confidence; others decay.
	type vh struct {
		Claim      string  `json:"claim"`
		Status     string  `json:"status"` // verified|rejected|inconclusive
		Confidence float64 `json:"confidence"`
		Category   string  `json:"root_cause_category,omitempty"`
	}
	var hyps struct {
		Hypotheses []struct {
			Claim      string   `json:"claim"`
			Supporting []string `json:"supporting_evidence_ids"`
			Confidence float64  `json:"confidence"`
			Category   string   `json:"root_cause_category,omitempty"`
		} `json:"hypotheses"`
	}
	startIdx := indexOf(prompt, "HYPOTHESES:")
	jsonStart := indexOfAnyFrom(prompt, startIdx, 0x7B)
	if jsonStart < 0 {
		return `{"verified":[]}`
	}
	if err := json.Unmarshal([]byte(prompt[jsonStart:]), &hyps); err != nil {
		return `{"verified":[]}`
	}
	verifyText := prompt
	if idx := indexOf(prompt, "VERIFICATION_EVIDENCE:"); idx >= 0 {
		verifyText = prompt[idx:]
	}
	out := make([]vh, 0, len(hyps.Hypotheses))
	for _, h := range hyps.Hypotheses {
		status := "inconclusive"
		conf := h.Confidence * 0.9
		if h.Category == "insufficient_evidence" {
			out = append(out, vh{Claim: h.Claim, Status: "inconclusive", Confidence: round2(conf), Category: h.Category})
			continue
		}
		matched := 0
		for _, id := range h.Supporting {
			if strings.Contains(verifyText, "["+id+"]") {
				matched++
			}
		}
		switch {
		case matched >= 2:
			status = "verified"
			conf = minF(h.Confidence+0.1, 0.95)
		case matched == 1:
			status = "verified"
			conf = h.Confidence
		default:
			status = "rejected"
			conf = h.Confidence * 0.5
		}
		out = append(out, vh{Claim: h.Claim, Status: status, Confidence: round2(conf), Category: h.Category})
	}
	b, _ := json.Marshal(map[string]any{"verified": out})
	return string(b)
}

func mockReport(prompt string) string {
	var hyps struct {
		Hypotheses []struct {
			Claim      string   `json:"claim"`
			Supporting []string `json:"supporting_evidence_ids"`
			Contradict []string `json:"contradicting_evidence_ids"`
			Confidence float64  `json:"confidence"`
			Category   string   `json:"root_cause_category,omitempty"`
		} `json:"hypotheses"`
	}
	startIdx := indexOf(prompt, "HYPOTHESES:")
	jsonStart := indexOfAnyFrom(prompt, startIdx, 0x7B)
	if jsonStart < 0 {
		return insufficientReport()
	}
	if err := json.Unmarshal([]byte(prompt[jsonStart:]), &hyps); err != nil {
		return insufficientReport()
	}
	// choose highest-confidence non-insufficient hypothesis
	best := -1
	for i, h := range hyps.Hypotheses {
		if h.Category == "insufficient_evidence" {
			continue
		}
		if best == -1 || h.Confidence > hyps.Hypotheses[best].Confidence {
			best = i
		}
	}
	if best == -1 || len(hyps.Hypotheses[best].Supporting) == 0 && len(hyps.Hypotheses) > 0 && allInsufficient(hyps.Hypotheses) {
		return insufficientReport()
	}
	bh := hyps.Hypotheses[best]
	rep := map[string]any{
		"summary":                bh.Claim,
		"root_cause":             bh.Claim,
		"root_cause_category":    bh.Category,
		"confidence":             bh.Confidence,
		"supporting_evidence":    bh.Supporting,
		"contradictory_evidence": bh.Contradict,
		"recommended_actions": []map[string]string{
			{"action": recommendedAction(bh.Category), "risk": "write",
				"Justification": "Address the identified root cause; requires operator approval."},
			{"action": "Add alerting on the affected metric threshold breached during this incident.", "risk": "read_only",
				"Justification": "Earlier detection of the same signature."},
		},
		"unresolved_questions": []string{},
	}
	if len(bh.Supporting) < 2 {
		rep["unresolved_questions"] = []string{"Additional evidence required to raise confidence above 0.7."}
	}
	b, _ := json.Marshal(rep)
	return string(b)
}

func allInsufficient(hs []struct {
	Claim      string   `json:"claim"`
	Supporting []string `json:"supporting_evidence_ids"`
	Contradict []string `json:"contradicting_evidence_ids"`
	Confidence float64  `json:"confidence"`
	Category   string   `json:"root_cause_category,omitempty"`
}) bool {
	for _, h := range hs {
		if h.Category != "insufficient_evidence" {
			return false
		}
	}
	return true
}

func insufficientReport() string {
	b, _ := json.Marshal(map[string]any{
		"summary":                       "Investigation completed without sufficient evidence to establish a root cause.",
		"root_cause":                    "",
		"root_cause_category":           "insufficient_evidence",
		"confidence":                    0.1,
		"supporting_evidence":           []string{},
		"contradictory_evidence":        []string{},
		"recommended_actions":           []map[string]string{{"action": "Extend logging/metrics coverage around the affected component.", "risk": "read_only", "Justification": "Current telemetry is insufficient."}},
		"unresolved_questions":          []string{"Which additional signals would discriminate between candidate causes?"},
		"affirms_insufficient_evidence": true,
	})
	return string(b)
}

func recommendedAction(category string) string {
	switch category {
	case "db_pool_regression":
		return "Restore POOL_SIZE to previous value (or higher) and redeploy; monitor DB wait events."
	case "n_plus_one_query":
		return "Batch the per-item query (JOIN or IN clause) and add ORM query-count assertions."
	case "cache_stampede":
		return "Add request coalescing and jittered TTLs; pre-warm cache before expiry."
	case "bad_deploy_config":
		return "Revert the configuration change and add config validation to deploy pipeline."
	case "connection_leak":
		return "Fix connection lifetime handling (close/release paths) and set conn max lifetime."
	default:
		return "Apply targeted remediation for " + category + "; validate with canary rollout."
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }
func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func indexOfAnyFrom(s string, from int, c byte) int {
	if from < 0 {
		from = 0
	}
	for i := from; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Test hooks used only by package-internal debugging tests.
func ParseEvidenceForTest(prompt string) []evItem { return parseEvidence(prompt) }
func MatchSignaturesForTest(text string) []int    { return matchSignatures(text) }
