// Package evidence persists the evidence graph: hypotheses, evidence nodes and
// typed edges linking evidence to hypotheses. Final agent claims must cite
// node IDs from this graph.
package evidence

import (
	"context"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool} }

// AddNode inserts an evidence node idempotently per (run_id, dedupe_hash).
func (s *Store) AddNode(ctx context.Context, n model.EvidenceNode) (model.EvidenceNode, error) {
	if n.ID == "" {
		n.ID = model.New()
	}
	if n.DedupeHash == "" {
		n.DedupeHash = retrieval.ContentHash(n.Type + "|" + n.Source + "|" + n.SourceReference + "|" + n.Content)
	}
	if n.TrustLevel == "" {
		n.TrustLevel = string(model.TrustToolOutput)
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO evidence_nodes
	    (id, run_id, chunk_id, type, source, source_reference, content, trust_level, dedupe_hash)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
	    ON CONFLICT (run_id, dedupe_hash) DO UPDATE SET content = EXCLUDED.content
	    RETURNING id, created_at`,
		n.ID, n.RunID, n.ChunkID, n.Type, n.Source, n.SourceReference, n.Content,
		n.TrustLevel, n.DedupeHash).Scan(&n.ID, &n.CreatedAt)
	return n, err
}

// AddHypothesis creates a hypothesis row for a run.
func (s *Store) AddHypothesis(ctx context.Context, h model.Hypothesis) (model.Hypothesis, error) {
	if h.ID == "" {
		h.ID = model.New()
	}
	if h.Status == "" {
		h.Status = "proposed"
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO hypotheses
	    (id, run_id, statement, confidence, status, rank, root_cause_category)
	    VALUES ($1,$2,$3,$4,$5,$6,$7)
	    RETURNING created_at`,
		h.ID, h.RunID, h.Statement, h.Confidence, h.Status, h.Rank,
		h.RootCauseCategory).Scan(&h.CreatedAt)
	return h, err
}

// Link connects an evidence node to a hypothesis with a typed relationship.
func (s *Store) Link(ctx context.Context, e model.EvidenceEdge) error {
	if e.ID == "" {
		e.ID = model.New()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO evidence_edges
	    (id, source_node_id, target_hypothesis_id, relationship, rationale, confidence)
	    VALUES ($1,$2,$3,$4,$5,$6)
	    ON CONFLICT (source_node_id, target_hypothesis_id, relationship) DO NOTHING`,
		e.ID, e.SourceNodeID, e.TargetHypothesisID, e.Relationship, e.Rationale, e.Confidence)
	return err
}

func (s *Store) Hypotheses(ctx context.Context, runID string) ([]model.Hypothesis, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, statement, confidence, status, rank, root_cause_category, created_at
	    FROM hypotheses WHERE run_id=$1 ORDER BY rank, confidence DESC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Hypothesis
	for rows.Next() {
		var h model.Hypothesis
		if err := rows.Scan(&h.ID, &h.RunID, &h.Statement, &h.Confidence, &h.Status,
			&h.Rank, &h.RootCauseCategory, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// SetStatus updates a hypothesis lifecycle status.
func (s *Store) SetStatus(ctx context.Context, hypID, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE hypotheses SET status=$2 WHERE id=$1`, hypID, status)
	return err
}

func (s *Store) Nodes(ctx context.Context, runID string) ([]model.EvidenceNode, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, run_id, chunk_id, type, source, source_reference, content, trust_level, dedupe_hash, created_at
	    FROM evidence_nodes WHERE run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.EvidenceNode
	for rows.Next() {
		var n model.EvidenceNode
		var chunkID *string
		if err := rows.Scan(&n.ID, &n.RunID, &chunkID, &n.Type, &n.Source,
			&n.SourceReference, &n.Content, &n.TrustLevel, &n.DedupeHash, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.ChunkID = chunkID
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) Edges(ctx context.Context, runID string) ([]model.EvidenceEdge, error) {
	rows, err := s.pool.Query(ctx, `SELECT e.id, e.source_node_id, e.target_hypothesis_id, e.relationship, e.rationale, e.confidence
	    FROM evidence_edges e JOIN evidence_nodes n ON n.id = e.source_node_id
	    WHERE n.run_id=$1 ORDER BY e.created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.EvidenceEdge
	for rows.Next() {
		var e model.EvidenceEdge
		if err := rows.Scan(&e.ID, &e.SourceNodeID, &e.TargetHypothesisID, &e.Relationship,
			&e.Rationale, &e.Confidence); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Graph returns the full evidence graph of a run.
func (s *Store) Graph(ctx context.Context, runID string) (*model.Graph, error) {
	hyps, err := s.Hypotheses(ctx, runID)
	if err != nil {
		return nil, err
	}
	nodes, err := s.Nodes(ctx, runID)
	if err != nil {
		return nil, err
	}
	edges, err := s.Edges(ctx, runID)
	if err != nil {
		return nil, err
	}
	return &model.Graph{Hypotheses: hyps, Nodes: nodes, Edges: edges}, nil
}

// EvidenceForHypothesis returns supporting and contradicting evidence IDs.
func (s *Store) EvidenceForHypothesis(ctx context.Context, hypID string) (supporting []string, contradicting []string, err error) {
	rows, err := s.pool.Query(ctx, `SELECT source_node_id, relationship FROM evidence_edges WHERE target_hypothesis_id=$1`, hypID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, rel string
		if err := rows.Scan(&id, &rel); err != nil {
			return nil, nil, err
		}
		switch rel {
		case model.EdgeSupports:
			supporting = append(supporting, id)
		case model.EdgeContradicts:
			contradicting = append(contradicting, id)
		}
	}
	return supporting, contradicting, rows.Err()
}
