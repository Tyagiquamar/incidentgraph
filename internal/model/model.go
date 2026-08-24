// Package model defines the core IncidentGraph domain types shared across packages.
package model

import "encoding/json"

// ---------------------------------------------------------------- enums

type TrustLevel string

const (
	TrustSystemTrusted   TrustLevel = "system_trusted"
	TrustUserProvided    TrustLevel = "user_provided"
	TrustInternalDoc     TrustLevel = "internal_document"
	TrustExternalUntrust TrustLevel = "external_untrusted"
	TrustToolOutput      TrustLevel = "tool_output"
)

type RiskLevel string

const (
	RiskReadOnly  RiskLevel = "read_only"
	RiskWrite     RiskLevel = "write"
	RiskPrivilege RiskLevel = "privileged"
)

// Run phases, in execution order.
var PhaseOrder = []string{
	"received", "context_build", "plan", "investigate",
	"hypothesis", "verify", "synthesize",
}

const (
	RunComplete      = "complete"
	RunFailed        = "failed"
	RunCancelled     = "cancelled"
	RunNeedsApproval = "needs_approval"
	RunRunning       = "running"
)

type PolicyDecision string

const (
	PolicyAllowed       PolicyDecision = "allowed"
	PolicyDenied        PolicyDecision = "denied"
	PolicyNeedsApproval PolicyDecision = "needs_approval"
)

// Evidence edge relationships.
const (
	EdgeSupports      = "SUPPORTS"
	EdgeContradicts   = "CONTRADICTS"
	EdgeDerivedFrom   = "DERIVED_FROM"
	EdgeDuplicates    = "DUPLICATES"
	EdgeCorrelatesWit = "CORRELATES_WITH"
)

// ---------------------------------------------------------------- entities

type Incident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Service     string    `json:"service"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	CreatedAt   TimeStamp `json:"created_at"`
}

type AgentRun struct {
	ID                string     `json:"id"`
	IncidentID        string     `json:"incident_id"`
	AgentBackend      string     `json:"agent_backend"`
	Model             string     `json:"model"`
	Status            string     `json:"status"`
	CurrentPhase      string     `json:"current_phase"`
	TerminationReason string     `json:"termination_reason,omitempty"`
	TotalTokens       int64      `json:"total_tokens"`
	TotalCostCents    float64    `json:"total_cost_cents"`
	LatencyMS         int64      `json:"latency_ms"`
	Error             string     `json:"error,omitempty"`
	StartedAt         TimeStamp  `json:"started_at"`
	CompletedAt       *TimeStamp `json:"completed_at,omitempty"`
}

type AgentStep struct {
	ID               string          `json:"id"`
	RunID            string          `json:"run_id"`
	StepNumber       int             `json:"step_number"`
	StepType         string          `json:"step_type"`
	State            string          `json:"state"`
	StructuredInput  json.RawMessage `json:"structured_input"`
	StructuredOutput json.RawMessage `json:"structured_output"`
	ContextManifest  json.RawMessage `json:"context_manifest"`
	LatencyMS        int64           `json:"latency_ms"`
	Error            string          `json:"error,omitempty"`
	CreatedAt        TimeStamp       `json:"created_at"`
}

type ToolCall struct {
	ID                 string          `json:"id"`
	RunID              string          `json:"run_id"`
	StepID             *string         `json:"step_id,omitempty"`
	ToolName           string          `json:"tool_name"`
	Arguments          json.RawMessage `json:"arguments"`
	RedactedArguments  json.RawMessage `json:"redacted_arguments"`
	RiskLevel          string          `json:"risk_level"`
	PolicyDecision     string          `json:"policy_decision"`
	Status             string          `json:"status"`
	Attempt            int             `json:"attempt"`
	ResultReference    string          `json:"result_reference,omitempty"`
	ResultSizeBytes    int             `json:"result_size_bytes"`
	Error              string          `json:"error,omitempty"`
	DurableExecutionID string          `json:"durable_execution_id,omitempty"`
	DurableNamespace   string          `json:"durable_namespace,omitempty"`
	IdempotencyKey     string          `json:"idempotency_key,omitempty"`
	RequestedAt        TimeStamp       `json:"requested_at"`
	StartedAt          *TimeStamp      `json:"started_at,omitempty"`
	CompletedAt        *TimeStamp      `json:"completed_at,omitempty"`
}

type ToolCallEvent struct {
	ID         int64           `json:"id"`
	ToolCallID string          `json:"tool_call_id"`
	EventType  string          `json:"event_type"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  TimeStamp       `json:"created_at"`
}

type Document struct {
	ID          string          `json:"id"`
	SourceType  string          `json:"source_type"`
	Service     string          `json:"service"`
	Path        string          `json:"path"`
	Title       string          `json:"title"`
	TrustLevel  string          `json:"trust_level"`
	ContentHash string          `json:"content_hash"`
	RawContent  string          `json:"-"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   TimeStamp       `json:"created_at"`
}

type Chunk struct {
	ID          string          `json:"chunk_id"`
	DocumentID  string          `json:"document_id"`
	ChunkIndex  int             `json:"chunk_index"`
	Content     string          `json:"text"`
	ContentHash string          `json:"content_hash"`
	TokenCount  int             `json:"token_count"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

type Hypothesis struct {
	ID                string    `json:"id"`
	RunID             string    `json:"run_id"`
	Statement         string    `json:"statement"`
	Confidence        float64   `json:"confidence"`
	Status            string    `json:"status"` // proposed|verified|rejected|selected
	Rank              int       `json:"rank"`
	RootCauseCategory string    `json:"root_cause_category,omitempty"`
	CreatedAt         TimeStamp `json:"created_at"`
}

type EvidenceNode struct {
	ID              string    `json:"id"`
	RunID           *string   `json:"run_id,omitempty"`
	ChunkID         *string   `json:"chunk_id,omitempty"`
	Type            string    `json:"type"` // log|doc|commit|metric|deployment|schema|tool_output|other
	Source          string    `json:"source"`
	SourceReference string    `json:"source_reference,omitempty"`
	Content         string    `json:"content"`
	TrustLevel      string    `json:"trust_level"`
	DedupeHash      string    `json:"-"`
	CreatedAt       TimeStamp `json:"created_at"`
}

type EvidenceEdge struct {
	ID                 string  `json:"id"`
	SourceNodeID       string  `json:"source_node_id"`
	TargetHypothesisID string  `json:"target_hypothesis_id"`
	Relationship       string  `json:"relationship"`
	Rationale          string  `json:"rationale,omitempty"`
	Confidence         float64 `json:"confidence"`
}

type Graph struct {
	Hypotheses []Hypothesis   `json:"hypotheses"`
	Nodes      []EvidenceNode `json:"nodes"`
	Edges      []EvidenceEdge `json:"edges"`
}

func (g *Graph) Empty() bool { return len(g.Nodes) == 0 && len(g.Hypotheses) == 0 }

type Approval struct {
	ID          string          `json:"id"`
	RunID       string          `json:"run_id"`
	ToolCallID  *string         `json:"tool_call_id,omitempty"`
	Tool        string          `json:"tool"`
	Arguments   json.RawMessage `json:"arguments"`
	Risk        string          `json:"risk"`
	Reason      string          `json:"reason,omitempty"`
	Status      string          `json:"status"` // pending|approved|rejected
	RequestedBy string          `json:"requested_by,omitempty"`
	DecidedBy   string          `json:"decided_by,omitempty"`
	DecidedAt   *TimeStamp      `json:"decided_at,omitempty"`
	CreatedAt   TimeStamp       `json:"created_at"`
}

type SecurityEvent struct {
	ID              int64     `json:"id"`
	RunID           *string   `json:"run_id,omitempty"`
	ToolCallID      *string   `json:"tool_call_id,omitempty"`
	Source          string    `json:"source"`
	Category        string    `json:"category"`
	DetectedContent string    `json:"detected_content"`
	Decision        string    `json:"decision"` // blocked|flagged|allowed
	CreatedAt       TimeStamp `json:"created_at"`
}

type RunEvent struct {
	Seq       int64           `json:"seq"`
	RunID     string          `json:"run_id"`
	EventType string          `json:"event_type"`
	Payload   json.RawMessage `json:"payload"`
	CreatedAt TimeStamp       `json:"created_at"`
}

type ModelUsage struct {
	ID            int64     `json:"id"`
	RunID         *string   `json:"run_id,omitempty"`
	EvalRunID     *string   `json:"eval_run_id,omitempty"`
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	TaskType      string    `json:"task_type"`
	InputTokens   int       `json:"input_tokens"`
	OutputTokens  int       `json:"output_tokens"`
	LatencyMS     int64     `json:"latency_ms"`
	EstimatedCost float64   `json:"estimated_cost"`
	Status        string    `json:"status"`
	RetryCount    int       `json:"retry_count"`
	Error         string    `json:"error,omitempty"`
	CreatedAt     TimeStamp `json:"created_at"`
}

// RetrievalResult is the structured unit returned by every retriever.
type RetrievalResult struct {
	ChunkID       string          `json:"chunk_id"`
	DocumentID    string          `json:"document_id"`
	Text          string          `json:"text"`
	LexicalScore  float64         `json:"lexical_score"`
	VectorScore   float64         `json:"vector_score"`
	CombinedScore float64         `json:"combined_score"`
	Rank          int             `json:"rank"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// ---------------------------------------------------------------- structured agent outputs

type InvestigationPlan struct {
	Objectives         []string `json:"objectives"`
	ToolsNeeded        []string `json:"tools_needed"`
	Risks              []string `json:"risks"`
	CompletionCriteria []string `json:"completion_criteria"`
}

type HypothesisCandidate struct {
	Claim                    string   `json:"claim"`
	SupportingEvidenceIDs    []string `json:"supporting_evidence_ids"`
	ContradictingEvidenceIDs []string `json:"contradicting_evidence_ids"`
	Confidence               float64  `json:"confidence"`
	RootCauseCategory        string   `json:"root_cause_category,omitempty"`
}

type HypothesisSet struct {
	Hypotheses []HypothesisCandidate `json:"hypotheses"`
}

type RecommendedAction struct {
	Action        string `json:"action"`
	Risk          string `json:"risk"`
	Justification string `json:"justification"`
}

type IncidentReport struct {
	Summary                     string              `json:"summary"`
	RootCause                   string              `json:"root_cause"`
	RootCauseCategory           string              `json:"root_cause_category,omitempty"`
	Confidence                  float64             `json:"confidence"`
	SupportingEvidence          []string            `json:"supporting_evidence"`
	ContradictoryEvidence       []string            `json:"contradictory_evidence"`
	RecommendedActions          []RecommendedAction `json:"recommended_actions"`
	UnresolvedQuestions         []string            `json:"unresolved_questions"`
	AffirmsInsufficientEvidence bool                `json:"affirms_insufficient_evidence,omitempty"`
}
