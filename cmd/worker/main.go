// Command worker re-drives runnable agent runs in a loop. The worker itself
// never owns a lease: it asks the backend runner to Resume, and the runner
// acquires its own fenced, heartbeat-renewed lease (single ownership path).
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
	if err := cfg.Validate(); err != nil {
		log.Error("invalid configuration", observability.F{"error": err.Error()})
		panic(err)
	}
	sys, err := bootstrap.Build(context.Background(), cfg)
	if err != nil {
		log.Error("bootstrap failed", observability.F{"error": err.Error()})
		panic(err)
	}
	ctx := context.Background()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	log.Info("worker started", observability.F{"owner": sys.Native.Owner(), "lease_ttl": cfg.RunLeaseTTL.String()})

	for range ticker.C {
		ids, err := sys.Runs.ClaimableRunIDs(ctx, 4)
		if err != nil {
			log.Warn("scan failed", observability.F{"error": err.Error()})
			continue
		}
		for _, id := range ids {
			// Runner atomically claims the fenced lease inside Resume; if
			// another driver wins, this attempt fails cleanly.
			go func(runID string) {
				bg := context.Background()
				if err := sys.Native.Resume(bg, runID); err != nil {
					log.Info("resume not taken", observability.F{"run_id": runID, "reason": err.Error()})
				}
			}(id)
		}
	}
}
