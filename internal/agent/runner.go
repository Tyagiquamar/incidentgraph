// Package agent implements pluggable agent runners and the native
// orchestrator. IncidentGraph owns lifecycle, persistence, policy, retrieval,
// evidence and evaluation; runner engines are interchangeable.
package agent

import "context"

// Runner is the engine interface. Engines are pluggable; Postgres remains the
// source of truth regardless of engine.
type Runner interface {
	// Start begins (or restarts) execution of a persisted run.
	Start(ctx context.Context, runID string) error
	// Resume continues a paused run (approval granted, crash recovery).
	Resume(ctx context.Context, runID string) error
	// Cancel requests cooperative cancellation.
	Cancel(ctx context.Context, runID string) error
}
