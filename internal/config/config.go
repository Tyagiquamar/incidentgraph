// Package config loads IncidentGraph configuration from environment variables
// with local-development defaults matching docker-compose.
package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL   string
	HTTPAddr      string
	Env           string // development | ci | production
	AuthEnabled   bool
	AdminToken    string
	OperatorToken string
	ViewerToken   string

	DurableMCPURL     string
	DurableMCPTimeout time.Duration

	LLMProvider        string // mock | openai
	LLMAPIKey          string
	LLMBaseURL         string
	CheapModel         string
	StrongModel        string
	JudgeModel         string
	EmbeddingModel     string
	EmbeddingDim       int
	LLMTimeout         time.Duration
	StructuredMaxRetry int

	HermesBaseURL string
	HermesEnabled bool
	MCPPublicURL  string // incidentgraph-mcp URL handed to external engines

	OpenClawVerifyToken    string
	OpenClawIngressEnabled bool

	// Budgets / loop protection defaults.
	MaxSteps           int
	MaxToolCalls       int
	MaxSameToolRepeats int
	MaxTokenBudget     int
	MaxCostBudgetCents int64
}

func Load() Config {
	return Config{
		DatabaseURL:   env("IG_DATABASE_URL", "postgres://incidentgraph:incidentgraph@localhost:5432/incidentgraph?sslmode=disable"),
		HTTPAddr:      env("IG_HTTP_ADDR", ":8090"),
		Env:           env("IG_ENV", "development"),
		AuthEnabled:   envBool("IG_AUTH_ENABLED", false),
		AdminToken:    env("IG_ADMIN_TOKEN", ""),
		OperatorToken: env("IG_OPERATOR_TOKEN", ""),
		ViewerToken:   env("IG_VIEWER_TOKEN", ""),

		DurableMCPURL:     env("IG_DURABLEMCP_URL", "http://localhost:8080"),
		DurableMCPTimeout: envDuration("IG_DURABLEMCP_TIMEOUT", 30*time.Second),

		LLMProvider:        env("IG_LLM_PROVIDER", "mock"),
		LLMAPIKey:          os.Getenv("IG_LLM_API_KEY"),
		LLMBaseURL:         env("IG_LLM_BASE_URL", "https://api.openai.com/v1"),
		CheapModel:         env("IG_MODEL_CHEAP", "gpt-4o-mini"),
		StrongModel:        env("IG_MODEL_STRONG", "gpt-4o"),
		JudgeModel:         env("IG_MODEL_JUDGE", "gpt-4o-mini"),
		EmbeddingModel:     env("IG_EMBEDDING_MODEL", "text-embedding-3-small"),
		EmbeddingDim:       envInt("IG_EMBEDDING_DIM", 1536),
		LLMTimeout:         envDuration("IG_LLM_TIMEOUT", 60*time.Second),
		StructuredMaxRetry: envInt("IG_STRUCTURED_MAX_RETRY", 2),

		HermesBaseURL: env("IG_HERMES_URL", "http://localhost:8123"),
		HermesEnabled: envBool("IG_HERMES_ENABLED", false),
		MCPPublicURL:  env("IG_MCP_PUBLIC_URL", ""),

		OpenClawVerifyToken:    os.Getenv("IG_OPENCLAW_VERIFY_TOKEN"),
		OpenClawIngressEnabled: envBool("IG_OPENCLAW_ENABLED", false),

		MaxSteps:           envInt("IG_MAX_STEPS", 40),
		MaxToolCalls:       envInt("IG_MAX_TOOL_CALLS", 25),
		MaxSameToolRepeats: envInt("IG_MAX_SAME_TOOL_REPEATS", 5),
		MaxTokenBudget:     envInt("IG_MAX_TOKEN_BUDGET", 200_000),
		MaxCostBudgetCents: envInt64("IG_MAX_COST_BUDGET_CENTS", 500),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}
