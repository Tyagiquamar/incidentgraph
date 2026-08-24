// Package ingest walks dataset directories and loads documents + incidents
// into the system via manifest.json files.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
)

type Manifest struct {
	Incident struct {
		Slug     string `json:"slug"`
		Title    string `json:"title"`
		Service  string `json:"service"`
		Severity string `json:"severity"`
	} `json:"incident"`
	Files []struct {
		Path       string `json:"path"`
		SourceType string `json:"source_type"`
		File       string `json:"file"`
		Trust      string `json:"trust"`
	} `json:"files"`
}

type Result struct {
	Slug     string   `json:"slug"`
	Incident string   `json:"incident_id,omitempty"`
	Docs     int      `json:"documents"`
	Chunks   int      `json:"chunks"`
	Errors   []string `json:"errors,omitempty"`
}

// LoadCorpus ingests every scenario directory under root that contains a
// manifest.json. Returns per-scenario results.
func LoadCorpus(ctx context.Context, ret *retrieval.Store, root string) ([]Result, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read datasets dir: %w", err)
	}
	var results []Result
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		manifestPath := filepath.Join(dir, "manifest.json")
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			continue // not a scenario dir
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			results = append(results, Result{Slug: e.Name(), Errors: []string{"bad manifest: " + err.Error()}})
			continue
		}
		res := ingestScenario(ctx, ret, dir, m)
		results = append(results, res)
	}
	return results, nil
}

func ingestScenario(ctx context.Context, ret *retrieval.Store, dir string, m Manifest) Result {
	res := Result{Slug: m.Incident.Slug}

	incID := model.New()
	if err := ret.Pool.QueryRow(ctx, `SELECT id FROM incidents WHERE title=$1`, m.Incident.Title).Scan(&incID); err != nil {
		if _, err2 := ret.Pool.Exec(ctx, `INSERT INTO incidents (id, title, description, service, severity, status)
		    VALUES ($1,$2,$3,$4,$5,'open')`,
			incID, m.Incident.Title,
			fmt.Sprintf("Synthetic incident fixture (%s): %s. Find the likely root cause and show evidence.",
				m.Incident.Slug, m.Incident.Title),
			m.Incident.Service, orSev(m.Incident.Severity)); err2 != nil {
			res.Errors = append(res.Errors, wrap("create incident", err2))
		}
	}
	res.Incident = incID

	docs, chunks, errs := IngestScenarioDocs(ctx, ret, dir, m)
	res.Docs += docs
	res.Chunks += chunks
	res.Errors = append(res.Errors, errs...)
	return res
}

// IngestScenarioDocs ingests only the documents of one scenario directory
// (no incident row). Used by the eval runner to give each case its own
// evidence corpus.
func IngestScenarioDocs(ctx context.Context, ret *retrieval.Store, dir string, m Manifest) (docs, chunks int, errs []string) {
	for _, f := range m.Files {
		raw, err := os.ReadFile(filepath.Join(dir, f.File))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", f.Path, err))
			continue
		}
		docID, n, err := ret.Ingest(ctx, retrieval.DocumentInput{
			SourceType: f.SourceType,
			Service:    m.Incident.Service,
			Path:       f.Path,
			Title:      titleFor(f.Path),
			TrustLevel: model.TrustLevel(orStr(f.Trust, string(model.TrustInternalDoc))),
			RawContent: string(raw),
			Metadata: map[string]any{
				"scenario":  m.Incident.Slug,
				"timestamp": "2026-08-23",
			},
		})
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", f.Path, err))
			continue
		}
		_ = docID
		docs++
		chunks += n
	}
	return docs, chunks, errs
}

// LoadManifest reads one scenario's manifest.json from a dataset directory.
func LoadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func titleFor(path string) string {
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func orSev(s string) string {
	if s == "" {
		return "sev3"
	}
	return s
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func wrap(what string, err error) string {
	if err == nil {
		return ""
	}
	return what + ": " + err.Error()
}
