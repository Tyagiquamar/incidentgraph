package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/model"
)

// RestartService is a side-effecting remediation tool. It is WRITE risk
// (deterministic policy => human approval required) and Durable (must execute
// through the DurableMCP substrate). The local Execute exists only to fail
// loudly if any code path ever tries to bypass durable execution.
type RestartService struct{}

func NewRestartService() *RestartService { return &RestartService{} }

func (t *RestartService) Def() Definition {
	return Definition{
		Name:        "restart_service",
		Description: "Restart an application service to apply remediation. Requires human approval and durable execution.",
		InputSchema: schema(map[string]any{
			"service": sProp("name of the service to restart"),
			"reason":  sProp("why the restart is required"),
		}, []string{"service"}),
		Risk:    model.RiskWrite,
		Timeout: 60 * time.Second,
		Durable: true,
	}
}

func (t *RestartService) Execute(ctx context.Context, runID string, args json.RawMessage) (*Result, error) {
	return nil, fmt.Errorf("restart_service must execute through DurableMCP; local execution refused by policy")
}

// Compile-time interface check.
var _ Executor = (*RestartService)(nil)
