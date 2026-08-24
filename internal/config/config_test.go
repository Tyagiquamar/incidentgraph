package config

import "testing"

func prod() Config {
	return Config{
		Env:                 "production",
		AuthEnabled:         true,
		AdminToken:          "a",
		OperatorToken:       "o",
		ViewerToken:         "v",
		ReadonlyDatabaseURL: "postgres://ro@db/ro",
		LLMProvider:         "mock",
	}
}

func TestProductionFailsClosedWithoutAuth(t *testing.T) {
	c := prod()
	c.AuthEnabled = false
	err := c.Validate()
	if err == nil {
		t.Fatal("production with auth disabled must be rejected")
	}
	for _, tok := range []string{"AdminToken", "OperatorToken", "ViewerToken"} {
		c = prod()
		switch tok {
		case "AdminToken":
			c.AdminToken = ""
		case "OperatorToken":
			c.OperatorToken = ""
		case "ViewerToken":
			c.ViewerToken = ""
		}
		if err := c.Validate(); err == nil {
			t.Fatalf("production without %s must be rejected", tok)
		}
	}
}

func TestProductionRequiresReadOnlyDSN(t *testing.T) {
	c := prod()
	c.ReadonlyDatabaseURL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("production without IG_READONLY_DATABASE_URL must be rejected")
	}
}

func TestOpenClawEnabledRequiresVerifyToken(t *testing.T) {
	c := prod()
	c.OpenClawIngressEnabled = true
	c.OpenClawVerifyToken = ""
	if err := c.Validate(); err == nil {
		t.Fatal("openclaw ingress without verify token must be rejected in any env")
	}
	c.OpenClawVerifyToken = "tok"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid openclaw config rejected: %v", err)
	}
}

func TestHermesRequiresMCPPublicURL(t *testing.T) {
	c := prod()
	c.HermesEnabled = true
	c.MCPPublicURL = ""
	if err := c.Validate(); err == nil {
		t.Fatal("hermes enabled without IG_MCP_PUBLIC_URL must be rejected")
	}
	c.MCPPublicURL = "http://mcp:8091/mcp"
	c.HermesBaseURL = "http://hermes:8123"
	if err := c.Validate(); err != nil {
		t.Fatalf("hermes with mcp url rejected: %v", err)
	}
}

func TestRealLLMRequiresAPIKey(t *testing.T) {
	c := prod()
	c.LLMProvider = "openai"
	c.LLMAPIKey = ""
	if err := c.Validate(); err == nil {
		t.Fatal("openai provider without api key must be rejected")
	}
	c.LLMAPIKey = "sk-..."
	if err := c.Validate(); err != nil {
		t.Fatalf("openai provider with key rejected: %v", err)
	}
}

func TestEmbeddingFallbackEnum(t *testing.T) {
	c := prod()
	c.EmbeddingFallback = "yes"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown embedding fallback mode must be rejected")
	}
	c.EmbeddingFallback = "hash"
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit hash fallback rejected: %v", err)
	}
}

func TestDevDefaultsRemainValid(t *testing.T) {
	c := Load()
	if err := c.Validate(); err != nil {
		t.Fatalf("default development config should validate: %v", err)
	}
}
