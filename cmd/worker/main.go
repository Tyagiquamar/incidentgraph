// Command worker re-drives active agent runs in a loop. In small deployments
// cmd/api already resumes runs at startup; run this to scale investigation
// throughput or recover runs while api stays read-only.
package main

import (
	"context"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/bootstrap"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/observability"
)

var log = observability.New("worker")

func main() {
	cfg := config.Load()
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		log.Error("bootstrap failed", observability.F{"error": err.Error()})
		panic(err)
	}
	ctx := context.Background()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	log.Info("worker started", observability.F{})
	for range ticker.C {
		// Claim one runnable run atomically (FOR UPDATE SKIP LOCKED + lease)
		// so multiple workers/apis never drive the same run concurrently.
		run, err := sys.Runs.ClaimNext(ctx, 10*time.Minute)
		if err != nil {
			log.Warn("claim failed", observability.F{"error": err.Error()})
			continue
		}
		if run == nil {
			continue // nothing claimable
		}
		if err := sys.Native.Resume(ctx, run.ID); err != nil {
			log.Warn("resume failed", observability.F{"run_id": run.ID, "error": err.Error()})
		}
		if err := sys.Runs.ReleaseLease(ctx, run.ID); err != nil {
			log.Warn("lease release failed", observability.F{"run_id": run.ID, "error": err.Error()})
		}
	}
}
