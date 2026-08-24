// Package bootstrap assembles the IncidentGraph runtime: database, retrieval,
// memory, policy, tools, LLM routing, durable execution client and the native
// agent runner. All binaries share this wiring.
package bootstrap

import (
	"context"

	"github.com/incidentgraph/incidentgraph/internal/agent"
	"github.com/incidentgraph/incidentgraph/internal/config"
	"github.com/incidentgraph/incidentgraph/internal/db"
	"github.com/incidentgraph/incidentgraph/internal/durablemcp"
	"github.com/incidentgraph/incidentgraph/internal/evidence"
	"github.com/incidentgraph/incidentgraph/internal/llm"
	"github.com/incidentgraph/incidentgraph/internal/memory"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/incidentgraph/incidentgraph/internal/observability"
	"github.com/incidentgraph/incidentgraph/internal/policy"
	"github.com/incidentgraph/incidentgraph/internal/retrieval"
	"github.com/incidentgraph/incidentgraph/internal/runs"
	"github.com/incidentgraph/incidentgraph/internal/security"
	"github.com/incidentgraph/incidentgraph/internal/tools"
	"github.com/jackc/pgx/v5/pgxpool"
)

type System struct {
	Cfg       config.Config
	Pool      *pgxpool.Pool
	Log       *observability.Logger
	Runs      *runs.Store
	Retrieval *retrieval.Store
	Memory    *memory.Store
	Security  *security.Store
	Policy    *policy.Engine
	Tools     *tools.Registry
	LLM       *llm.Router
	Durable   *durablemcp.Client // nil if not configured
	Native    *agent.NativeRunner
}

// Build connects and wires the full system.
func Build(ctx context.Context, cfg config.Config) (*System, error) {
	log := observability.New("bootstrap")
	pool, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		return nil, err
	}
	log.Info("database ready", observability.F{})

	var emb retrieval.Embedder
	if cfg.LLMProvider == "openai" && cfg.LLMAPIKey != "" {
		emb = retrieval.NewOpenAIEmbedder(cfg.LLMBaseURL, cfg.LLMAPIKey, cfg.EmbeddingModel, cfg.EmbeddingDim)
	} else {
		emb = retrieval.NewHashEmbedder(cfg.EmbeddingDim)
	}

	ret := retrieval.NewStore(pool, emb)
	mem := memory.NewStore(pool, emb)
	sec := security.NewStore(pool)

	eng := policy.New()
	registry := tools.NewRegistry(
		tools.NewSearchDocs(pool, ret),
		tools.NewSearchLogs(pool, ret),
		tools.NewSearchCode(pool, ret),
		tools.NewGetDeployment(pool, ret),
		tools.NewGetGitDiff(pool, ret),
		tools.NewReadFile(pool, ret),
		tools.NewQueryMetrics(pool, ret),
		tools.NewQueryPostgres(pool, ret, func(sqlText string) error {
			d := eng.Evaluate("query_postgres_readonly", mustJSON(map[string]string{"sql": sqlText}))
			if d.Decision != model.PolicyAllowed {
				return &toolPolicyError{msg: d.Reason}
			}
			return nil
		}),
		// WRITE-risk + durable: exercisable end-to-end through approval pause,
		// human decision and the DurableMCP substrate. Never executed locally.
		tools.NewRestartService(),
	)

	runStore := runs.NewStore(pool)
	recorder := llm.UsageRecorder(func(rec llm.UsageRecord) {
		_ = runStore.RecordUsage(ctx, rec.RunID, rec)
	})
	var primary, fallback, judge llm.Provider
	switch cfg.LLMProvider {
	case "openai":
		base := llm.NewOpenAI(cfg.LLMBaseURL, cfg.LLMAPIKey, "")
		primary = base.WithModel(cfg.StrongModel)
		fallback = base.WithModel(cfg.CheapModel)
		judge = base.WithModel(cfg.JudgeModel)
	default:
		primary = llm.NewMock("mock-large")
		fallback = llm.NewMock("mock-small")
		judge = llm.NewMock("mock-small")
	}
	router := llm.NewRouter(primary, fallback, judge, recorder, cfg.StructuredMaxRetry)

	var durable *durablemcp.Client
	if cfg.DurableMCPURL != "" {
		durable = durablemcp.New(cfg.DurableMCPURL, envOr("IG_DURABLEMCP_READER_KEY"), cfg.DurableMCPTimeout)
	}

	nativeRunner := agent.NewNative(agent.Deps{
		Runs: runStore, Policy: eng, Tools: registry,
		Evidence: evidence.NewStore(pool), Memory: mem, Retrieval: ret,
		LLM: router, Security: sec, Durable: durable,
		Budgets: agent.Budgets{
			MaxSteps:           cfg.MaxSteps,
			MaxToolCalls:       cfg.MaxToolCalls,
			MaxSameToolRepeats: cfg.MaxSameToolRepeats,
			MaxTokenBudget:     cfg.MaxTokenBudget,
			MaxCostCents:       float64(cfg.MaxCostBudgetCents),
		},
		Log: observability.New("native-runner"),
	})

	return &System{
		Cfg: cfg, Pool: pool, Log: log,
		Runs: runStore, Retrieval: ret, Memory: mem, Security: sec,
		Policy: eng, Tools: registry, LLM: router, Durable: durable, Native: nativeRunner,
	}, nil
}

type toolPolicyError struct{ msg string }

func (e *toolPolicyError) Error() string { return e.msg }

func mustJSON(v any) []byte {
	b, _ := jsonMarshal(v)
	return b
}

func envOr(key string) string { return osGetenv(key) }
