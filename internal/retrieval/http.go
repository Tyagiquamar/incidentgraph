package retrieval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func newHTTPClient(timeoutSec int) *httpClient {
	return &httpClient{c: &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}}
}

type httpClient struct{ c *http.Client }

func (h *httpClient) postJSON(url, apiKey string, body any, out any) error {
	return h.postJSONCtx(context.Background(), url, apiKey, body, out)
}

func (h *httpClient) postJSONCtx(ctx context.Context, url, apiKey string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return &statusError{Code: resp.StatusCode, Body: string(raw)}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type statusError struct {
	Code int
	Body string
}

func (e *statusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("http %d: %s", e.Code, truncateForErr(e.Body))
	}
	return http.StatusText(e.Code)
}

func truncateForErr(s string) string {
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
