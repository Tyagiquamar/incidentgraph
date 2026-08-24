package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/incidentgraph/incidentgraph/internal/contextx"
	"github.com/incidentgraph/incidentgraph/internal/evidence"
	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/runs"
)

// ---------------------------------------------------------------- hypothesis

func (r *NativeRunner) phaseHypothesis(ctx context.Context, run *model.AgentRun, lease runs.Lease) error {
	nodes, err := r.deps.Evidence.Nodes(ctx, run.ID)
	if err != nil {
		return err
	}
	items := nodesToContextItems(nodes)
	prompt := "TASK: hypotheses\n" + contextx.RenderEvidenceBlock(items)

	var set model.HypothesisSet
	if err := r.deps.LLM.GenerateStructured(ctx, llm.GenRequest{
		RunID:    run.ID,
		Task:     llm.TaskHypothesisSynthesis,
		System:   systemPrompt(),
		Messages: []llm.Message{{Role: llm.RoleUser, Content: prompt}},
	}, &set); err != nil {
		return fmt.Errorf("hypothesis generation: %w", err)
	}

	nodeIDs := map[string]bool{}
	for _, n := range nodes {
		nodeIDs[n.ID] = true
		// Accept the short display form ("E-"+first8 of dashed-stripped id)
		// used inside prompts, plus the raw id, when resolving references.
		nodeIDs[shortIDOf(n)] = true
		nodeIDs[strings.ReplaceAll(strings.ToLower(n.ID), "-", "")[:8]] = true
	}
	rank := 0
	for _, hc := range set.Hypotheses {
		h, err := r.deps.Evidence.AddHypothesis(ctx, model.Hypothesis{
			RunID: run.ID, Statement: hc.Claim, Confidence: hc.Confidence,
			Status: "proposed", Rank: rank, RootCauseCategory: hc.RootCauseCategory,
		})
		if err != nil {
			return err
		}
		rank++
		linkEvidence(ctx, r.deps.Evidence, nodeIDs, h.ID, hc.SupportingEvidenceIDs, model.EdgeSupports)
		linkEvidence(ctx, r.deps.Evidence, nodeIDs, h.ID, hc.ContradictingEvidenceIDs, model.EdgeContradicts)
	}
	_ = r.deps.Memory.PutWorking(ctx, run.ID, "hypotheses", string(marshal(set)))
	if err := r.deps.Runs.AddStep(ctx, model.AgentStep{
		RunID:            run.ID,
		StepType:         phaseHypothesis,
		StructuredInput:  marshal(map[string]any{"evidence_count": len(nodes)}),
		StructuredOutput: marshal(set),
	}); err != nil {
		return err
	}
	r.emit(ctx, run.ID, "step_completed", map[string]any{"step": phaseHypothesis, "count": len(set.Hypotheses)})
	return r.setPhase(ctx, lease, run, phaseVerify)
}

// linkEvidence resolves evidence-ID references into typed edges.
func linkEvidence(ctx context.Context, ev *evidence.Store, known map[string]bool, hypID string, refs []string, rel string) {
	for _, ref := range refs {
		id := normalizeEvidenceRef(ref)
		if !known[id] {
			continue // hallucinated reference — never linked
		}
		_ = ev.Link(ctx, model.EvidenceEdge{
			SourceNodeID: id, TargetHypothesisID: hypID, Relationship: rel,
			Rationale: "cited by hypothesis synthesis", Confidence: 0.8,
		})
	}
}

// normalizeEvidenceRef maps "E-ab12cd34" back to the underlying node ID.
func normalizeEvidenceRef(ref string) string {
	ref = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(ref, "["), "]"))
	if strings.HasPrefix(ref, "E-") && len(ref) == 10 {
		return ref[2:]
	}
	return ref
}

// nodesToContextItems converts evidence rows to context items with stable IDs.
// Source falls back to the tool attribution when the result carries no
// reference (search tools), so provenance headers never render empty.
func nodesToContextItems(nodes []model.EvidenceNode) []contextx.Item {
	items := make([]contextx.Item, 0, len(nodes))
	for _, n := range nodes {
		src := n.SourceReference
		if strings.TrimSpace(src) == "" {
			src = n.Source
		}
		items = append(items, contextx.Item{
			Content:        n.Content,
			Source:         src,
			Type:           n.Type,
			Trust:          model.TrustLevel(n.TrustLevel),
			RetrievalScore: 1.0,
			EvidenceID:     shortIDOf(n),
		})
	}
	return items
}

// shortIDOf renders the display ID used in prompts: E-<first8 of uuid>.
func shortIDOf(n model.EvidenceNode) string { return "E-" + strings.ReplaceAll(n.ID, "-", "")[:8] }

// ---------------------------------------------------------------- verify

func (r *NativeRunner) phaseVerify(ctx context.Context, run *model.AgentRun, lease runs.Lease) error {
	hyps, err := r.deps.Evidence.Hypotheses(ctx, run.ID)
	if err != nil {
		return err
	}
	nodes, _ := r.deps.Evidence.Nodes(ctx, run.ID)
	items := nodesToContextItems(nodes)

	// verification pass: gather one more discriminating metric per top hypothesis
	for i, h := range hyps {
		if i >= 2 {
			break
		}
		if series := verifySeriesFor(h); series != "" {
			if exec, ok := r.deps.Tools.Get("query_metrics"); ok {
				args := marshal(map[string]any{"series": series, "service": r.serviceName(ctx, run)})
				res, err := exec.Execute(ctx, run.ID, args)
				if err == nil && res != nil {
					n, err := r.deps.Evidence.AddNode(ctx, model.EvidenceNode{
						RunID: strPtr(run.ID), Type: "metric", Source: "tool:query_metrics",
						SourceReference: series + "/verify", Content: trunc(res.Text, 900),
						TrustLevel: string(model.TrustToolOutput),
					})
					if err == nil {
						items = append(items, contextx.Item{Content: n.Content, Source: n.SourceReference,
							Type: "metric", Trust: model.TrustToolOutput, RetrievalScore: 1.2, EvidenceID: shortIDOf(n)})
					}
				}
			}
		}
	}

	payload := struct {
		Hypotheses []model.Hypothesis `json:"hypotheses"`
	}{Hypotheses: hyps}
	prompt := "TASK: verify\nVERIFICATION_EVIDENCE:\n" + contextx.RenderEvidenceBlock(items) +
		"\nHYPOTHESES: " + string(marshal(payload))

	var out struct {
		Verified []struct {
			Claim      string  `json:"claim"`
			Status     string  `json:"status"`
			Confidence float64 `json:"confidence"`
			Category   string  `json:"root_cause_category,omitempty"`
		} `json:"verified"`
	}
	if err := r.deps.LLM.GenerateStructured(ctx, llm.GenRequest{
		RunID:    run.ID,
		Task:     llm.TaskClassification,
		System:   systemPrompt(),
		Messages: []llm.Message{{Role: llm.RoleUser, Content: prompt}},
	}, &out); err != nil {
		return fmt.Errorf("verification: %w", err)
	}
	for _, v := range out.Verified {
		for _, h := range hyps {
			if statementsMatch(h.Statement, v.Claim) {
				status := v.Status
				if status != "verified" && status != "rejected" && status != "inconclusive" {
					status = "inconclusive"
				}
				_ = r.deps.Evidence.SetStatus(ctx, h.ID, status)
				if status == "rejected" {
					_ = r.deps.Evidence.Link(ctx, model.EvidenceEdge{
						TargetHypothesisID: h.ID, Relationship: model.EdgeContradicts,
						Rationale: "verification rejected", Confidence: v.Confidence,
					})
				}
			}
		}
	}
	if err := r.deps.Runs.AddStep(ctx, model.AgentStep{
		RunID:            run.ID,
		StepType:         phaseVerify,
		StructuredInput:  marshal(map[string]any{"hypotheses": len(hyps)}),
		StructuredOutput: marshal(out),
	}); err != nil {
		return err
	}
	r.emit(ctx, run.ID, "step_completed", map[string]any{"step": phaseVerify})
	return r.setPhase(ctx, lease, run, phaseSynthesize)
}

// statementsMatch is a conservative containment check for claim matching.
func statementsMatch(a, b string) bool {
	an := normalizeClaim(a)
	bn := normalizeClaim(b)
	return an == bn || strings.Contains(an, bn) || strings.Contains(bn, an) ||
		jaccard(words(an), words(bn)) > 0.55
}

func normalizeClaim(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r == ' ' {
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func words(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(s) {
		if len(w) > 2 {
			out[w] = true
		}
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	inter, union := 0, len(a)+len(b)
	for k := range a {
		if b[k] {
			inter++
		}
	}
	union -= inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func verifySeriesFor(h model.Hypothesis) string {
	cat := h.RootCauseCategory
	lower := strings.ToLower(h.Statement + " " + cat)
	switch {
	case strings.Contains(lower, "pool") || cat == "db_pool_regression":
		return "db_wait_ms"
	case strings.Contains(lower, "cache") || strings.Contains(lower, "redis"):
		return "redis_latency_ms"
	case cat == "n_plus_one_query":
		return "p99_latency_ms"
	default:
		return ""
	}
}

func (r *NativeRunner) serviceName(ctx context.Context, run *model.AgentRun) string {
	if inc, err := r.incident(ctx, run); err == nil {
		return inc.Service
	}
	return "checkout"
}

// ---------------------------------------------------------------- synthesize

func (r *NativeRunner) phaseSynthesize(ctx context.Context, run *model.AgentRun, lease runs.Lease) error {
	hyps, err := r.deps.Evidence.Hypotheses(ctx, run.ID)
	if err != nil {
		return err
	}
	nodes, _ := r.deps.Evidence.Nodes(ctx, run.ID)
	items := nodesToContextItems(nodes)

	prompt := "TASK: report\n" + contextx.RenderEvidenceBlock(items) +
		"\nHYPOTHESES: " + string(marshal(map[string]any{"hypotheses": hyps}))

	var report model.IncidentReport
	if err := r.deps.LLM.GenerateStructured(ctx, llm.GenRequest{
		RunID:    run.ID,
		Task:     llm.TaskHypothesisSynthesis,
		System:   systemPrompt(),
		Messages: []llm.Message{{Role: llm.RoleUser, Content: prompt}},
	}, &report); err != nil {
		return fmt.Errorf("report generation: %w", err)
	}

	// mark selected / rejected hypotheses based on the final report
	for _, h := range hyps {
		if statementsMatch(h.Statement, report.RootCause) {
			_ = r.deps.Evidence.SetStatus(ctx, h.ID, "selected")
		}
	}

	// validate that cited evidence exists; drop phantom citations and count them
	validIDs := map[string]string{} // short -> full
	for _, n := range nodes {
		validIDs[shortIDOf(n)] = n.ID
	}
	report.SupportingEvidence = filterCitations(report.SupportingEvidence, validIDs)
	report.ContradictoryEvidence = filterCitations(report.ContradictoryEvidence, validIDs)

	if err := r.deps.Runs.AddStep(ctx, model.AgentStep{
		RunID:            run.ID,
		StepType:         phaseSynthesize,
		StructuredInput:  marshal(map[string]any{"prompt": prompt}),
		StructuredOutput: marshal(report),
	}); err != nil {
		return err
	}
	_ = r.deps.Memory.PutWorking(ctx, run.ID, "final_report", string(marshal(report)))
	r.emit(ctx, run.ID, "report_ready", map[string]any{
		"root_cause": report.RootCause, "confidence": report.Confidence,
		"supporting_evidence": len(report.SupportingEvidence)})
	return r.setPhase(ctx, lease, run, phaseComplete)
}

func filterCitations(citations []string, valid map[string]string) []string {
	out := make([]string, 0, len(citations))
	for _, c := range citations {
		key := normalizeEvidenceRef(c)
		if strings.HasPrefix(key, "E-") {
			if _, ok := valid[key]; ok {
				out = append(out, key)
			}
			continue
		}
		if _, ok := valid[c]; ok {
			out = append(out, c)
		}
	}
	return out
}
