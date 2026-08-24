// Package memory implements the three explicit memory layers:
//
//	working  — current run state (plan, observations, hypotheses, open questions)
//	episodic — trajectories of past incidents (what was investigated, what fixed it)
//	semantic — embedded past incidents / failure patterns retrievable via pgvector
//
// Memory is UNTRUSTED context: retrieval results carry trust levels and never
// override instructions.
package memory

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	emb  retrieval.Embedder
}

func NewStore(pool *pgxpool.Pool, emb retrieval.Embedder) *Store {
	return &Store{pool, emb}
}

type Item struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"` // working|episodic|semantic
	RunID    *string         `json:"run_id,omitempty"`
	Incident *string         `json:"incident_id,omitempty"`
	Key      string          `json:"key"`
	Content  string          `json:"content"`
	Metadata json.RawMessage `json:"metadata,omitempty"`
	Score    float64         `json:"score,omitempty"` // similarity when retrieved semantically
}

// PutWorking stores/overwrites a working-memory entry for a run.
func (s *Store) PutWorking(ctx context.Context, runID, key, content string) error {
	meta, _ := json.Marshal(map[string]any{"layer": "working"})
	_, err := s.pool.Exec(ctx, `DELETE FROM memories WHERE kind='working' AND run_id=$1 AND key=$2`, runID, key)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO memories (id, kind, run_id, key, content, metadata)
	    VALUES ($1,'working',$2,$3,$4,$5)`, model.New(), runID, key, content, meta)
	return err
}

func (s *Store) Working(ctx context.Context, runID string) ([]Item, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, run_id, incident_id, key, content, metadata
	    FROM memories WHERE kind='working' AND run_id=$1 ORDER BY created_at`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Kind, &it.RunID, &it.Incident, &it.Key, &it.Content, &it.Metadata); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// PutEpisodic records a completed investigation trajectory for future runs.
func (s *Store) PutEpisodic(ctx context.Context, incidentID, key, content string, metadata map[string]any) error {
	meta, _ := json.Marshal(metadata)
	vec := s.emb.Embed(content)
	_, err := s.pool.Exec(ctx, `INSERT INTO memories (id, kind, incident_id, key, content, metadata, embedding)
	    VALUES ($1,'episodic',$2,$3,$4,$5,$6::vector)`,
		model.New(), incidentID, key, content, meta, retrieval.VectorLiteral(vec))
	return err
}

// EpisodicRecent returns the most recent episodic memories (optionally service-filtered).
func (s *Store) EpisodicRecent(ctx context.Context, limit int) ([]Item, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, run_id, incident_id, key, content, metadata
	    FROM memories WHERE kind='episodic' ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Kind, &it.RunID, &it.Incident, &it.Key, &it.Content, &it.Metadata); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// PutSemantic embeds and stores a semantic memory (failure pattern, service note).
func (s *Store) PutSemantic(ctx context.Context, incidentID, key, content string, metadata map[string]any) error {
	return s.PutEpisodicKind(ctx, "semantic", incidentID, key, content, metadata)
}

func (s *Store) PutEpisodicKind(ctx context.Context, kind, incidentID, key, content string, metadata map[string]any) error {
	meta, _ := json.Marshal(metadata)
	vec := s.emb.Embed(content)
	_, err := s.pool.Exec(ctx, fmt.Sprintf(`INSERT INTO memories (id, kind, incident_id, key, content, metadata, embedding)
	    VALUES ($1,'%s',$2,$3,$4,$5,$6::vector)`, kind),
		model.New(), incidentID, key, content, meta, retrieval.VectorLiteral(vec))
	return err
}

// SemanticSearch retrieves the top-k similar memories via pgvector cosine.
func (s *Store) SemanticSearch(ctx context.Context, query string, k int) ([]Item, error) {
	vec := retrieval.VectorLiteral(s.emb.Embed(query))
	rows, err := s.pool.Query(ctx, `SELECT id, kind, run_id, incident_id, key, content, metadata,
	        1 - (embedding <=> $1::vector) AS score
	    FROM memories WHERE embedding IS NOT NULL AND kind IN ('episodic','semantic')
	    ORDER BY embedding <=> $1::vector LIMIT $2`, vec, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Kind, &it.RunID, &it.Incident, &it.Key, &it.Content, &it.Metadata, &it.Score); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}
