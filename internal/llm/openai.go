package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OpenAIProvider calls an OpenAI-compatible chat-completions endpoint.
type OpenAIProvider struct {
	BaseURL string
	APIKey  string
	Model   string
	client  *http.Client
}

func NewOpenAI(baseURL, apiKey, model string) *OpenAIProvider {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAIProvider{BaseURL: baseURL, APIKey: apiKey, Model: model,
		client: &http.Client{Timeout: 90 * time.Second}}
}

func (p *OpenAIProvider) Name() string { return "openai" }

// WithModel returns a shallow copy pointed at another model tier.
func (p *OpenAIProvider) WithModel(model string) *OpenAIProvider {
	cp := *p
	cp.Model = model
	return &cp
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

func (p *OpenAIProvider) Generate(ctx context.Context, req GenRequest) (*GenResponse, error) {
	messages := make([]chatMessage, 0, len(req.Messages)+1)
	if req.System != "" {
		messages = append(messages, chatMessage{Role: "system", Content: req.System})
	}
	for _, m := range req.Messages {
		messages = append(messages, chatMessage{Role: string(m.Role), Content: m.Content})
	}
	body := map[string]any{
		"model":       p.Model,
		"messages":    messages,
		"temperature": req.Temperature,
	}
	if req.MaxTokens > 0 {
		body["max_tokens"] = req.MaxTokens
	}
	if req.Structured {
		body["response_format"] = map[string]string{"type": "json_object"}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.BaseURL+"/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	start := time.Now()
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("openai http %d: %s", resp.StatusCode, truncateStr(string(raw), 300))
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("openai decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("openai returned no choices")
	}
	return &GenResponse{
		Text:         out.Choices[0].Message.Content,
		InputTokens:  out.Usage.PromptTokens,
		OutputTokens: out.Usage.CompletionTokens,
		LatencyMS:    time.Since(start).Milliseconds(),
		Model:        p.Model,
		Provider:     p.Name(),
		FinishReason: out.Choices[0].FinishReason,
	}, nil
}
