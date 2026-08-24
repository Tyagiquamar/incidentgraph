// Package evalsdata embeds the evaluation case dataset.
package evalsdata

import (
	"embed"
	"encoding/json"

	"github.com/incidentgraph/incidentgraph/internal/evals"
)

//go:embed cases.json
var casesFS embed.FS

// Load parses the embedded case dataset.
func Load() ([]evals.Case, error) {
	b, err := casesFS.ReadFile("cases.json")
	if err != nil {
		return nil, err
	}
	var out []evals.Case
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
