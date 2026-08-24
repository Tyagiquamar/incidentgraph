// Package config loads IncidentGraph configuration from environment variables
// with local-development defaults matching docker-compose.
//
// Validate() enforces fail-closed production rules BEFORE any binary starts:
// an insecure production configuration must refuse to boot, never degrade
// silently into an unauthenticated or misconfigured state.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	DatabaseURL         string
	ReadonlyDatabaseURL string // separate read-only DSN (defense in depth)
	HTTPAddr            string
	Env                 string // development | ci | production
	AuthEnabled         bool
	AdminToken          string
	OperatorToken       string
	ViewerToken         string

	DurableMCPURL     string
	DurableMCPTimeout time.Duration

	// Run lease: drivers claim runs for TTL and renew at TTL/3.
	RunLeaseTTL time.Duration

	MCPAddr        string
	MCPAuthEnabled bool
	MCPAuthToken   string

	LLMProvider        string // mock | openai
	LLMAPIKey          string
	LLMBaseURL         string
	CheapModel         string
	StrongModel        string
	JudgeModel         string
	EmbeddingModel     string
	EmbeddingDim       int
	EmbeddingFallback  string // disabled | hash
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
		DatabaseURL:         env("IG_DATABASE_URL", "postgres://incidentgraph:incidentgraph@localhost:5432/incidentgraph?sslmode=disable"),
		ReadonlyDatabaseURL: os.Getenv("IG_READONLY_DATABASE_URL"),
		HTTPAddr:            env("IG_HTTP_ADDR", ":8090"),
		Env:                 env("IG_ENV", "development"),
		AuthEnabled:         envBool("IG_AUTH_ENABLED", false),
		AdminToken:          env("IG_ADMIN_TOKEN", ""),
		OperatorToken:       env("IG_OPERATOR_TOKEN", ""),
		ViewerToken:         env("IG_VIEWER_TOKEN", ""),

		DurableMCPURL:     env("IG_DURABLEMCP_URL", "http://localhost:8080"),
		DurableMCPTimeout: envDuration("IG_DURABLEMCP_TIMEOUT", 30*time.Second),

		RunLeaseTTL: envDuration("IG_RUN_LEASE_TTL", 60*time.Second),

		MCPAddr:        env("IG_MCP_ADDR", ":8091"),
		MCPAuthEnabled: envBool("IG_MCP_AUTH_ENABLED", false),
		MCPAuthToken:   os.Getenv("IG_MCP_TOKEN"),

		LLMProvider:    env("IG_LLM_PROVIDER", "mock"),
		LLMAPIKey:      os.Getenv("IG_LLM_API_KEY"),
		LLMBaseURL:     env("IG_LLM_BASE_URL", "https://api.openai.com/v1"),
		CheapModel:     env("IG_MODEL_CHEAP", "gpt-4o-mini"),
		StrongModel:    env("IG_MODEL_STRONG", "gpt-4o"),
		JudgeModel:     env("IG_MODEL_JUDGE", "gpt-4o-mini"),
		EmbeddingModel: env("IG_EMBEDDING_MODEL", "text-embedding-3-small"),
		EmbeddingDim:   envInt("IG_EMBEDDING_DIM", 1536),
		EmbeddingFallback: func() string {
			v := env("IG_EMBEDDING_FALLBACK", "disabled")
			if v != "disabled" && v != "hash" {
				return "disabled"
			}
			return v
		}(),
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

// Validate fails closed on insecure/incoherent configuration. It is called by
// every binary before serving traffic.
func (c Config) Validate() error {
	if c.Env == "production" {
		if !c.AuthEnabled {
			return fmt.Errorf("production requires IG_AUTH_ENABLED=true")
		}
		for name, tok := range map[string]string{
			"IG_ADMIN_TOKEN":    c.AdminToken,
			"IG_OPERATOR_TOKEN": c.OperatorToken,
			"IG_VIEWER_TOKEN":   c.ViewerToken,
		} {
			if tok == "" {
				return fmt.Errorf("production requires %s to be set", name)
			}
		}
		if c.ReadonlyDatabaseURL == "" {
			return fmt.Errorf("production requires IG_READONLY_DATABASE_URL (read-only SQL must not run on the primary write pool)")
		}
	}

	if c.OpenClawIngressEnabled && c.OpenClawVerifyToken == "" {
		return fmt.Errorf("IG_OPENCLAW_ENABLED=true requires IG_OPENCLAW_VERIFY_TOKEN (unauthenticated ingress is never allowed)")
	}

	if c.LLMProvider == "openai" && c.LLMAPIKey == "" {
		return fmt.Errorf("IG_LLM_PROVIDER=openai requires IG_LLM_API_KEY")
	}
	if c.EmbeddingFallback != "" && c.EmbeddingFallback != "disabled" && c.EmbeddingFallback != "hash" {
		return fmt.Errorf("IG_EMBEDDING_FALLBACK must be disabled|hash, got %q", c.EmbeddingFallback)
	}

	if c.HermesEnabled {
		if c.MCPPublicURL == "" {
			return fmt.Errorf("IG_HERMES_ENABLED=true requires IG_MCP_PUBLIC_URL (the MCP endpoint Hermes will call)")
		}
		if c.HermesBaseURL == "" {
			return fmt.Errorf("IG_HERMES_ENABLED=true requires IG_HERMES_URL")
		}
	}

	return nil
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
