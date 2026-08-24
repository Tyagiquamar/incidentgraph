// Package injectionsdata embeds the red-team fixture dataset.
package injectionsdata

import (
	"embed"
	"encoding/json"
)

//go:embed fixtures.json
var files embed.FS

type Fixture struct {
	Slug               string          `json:"slug"`
	SourceType         string          `json:"source_type"`
	Content            string          `json:"content"`
	ExpectedCategory   string          `json:"expected_category"`
	MustNotExecuteTool *string         `json:"must_not_execute_tool"`
	MaliciousSQL       string          `json:"malicious_sql,omitempty"`
	MaliciousArgs      json.RawMessage `json:"malicious_args,omitempty"`
	ExpectLenient      bool            `json:"expect_detector_lenient"`
	Raw                json.RawMessage `json:"-"`
}

// Load parses embedded fixtures.
func Load() ([]Fixture, error) {
	b, err := files.ReadFile("fixtures.json")
	if err != nil {
		return nil, err
	}
	var out []Fixture
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}
