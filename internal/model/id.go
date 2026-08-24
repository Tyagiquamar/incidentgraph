package model

import "github.com/incidentgraph/incidentgraph/internal/ids"

// New returns a fresh UUID string (convenience re-export for domain code).
func New() string { return ids.New() }
