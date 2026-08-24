package retrieval

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

func newHTTPClient(timeoutSec int) *httpClient {
	return &httpClient{c: &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}}
}

type httpClient struct{ c *http.Client }

func (h *httpClient) postJSON(url, apiKey string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
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
		return &statusError{Code: resp.StatusCode}
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type statusError struct{ Code int }

func (e *statusError) Error() string {
	return http.StatusText(e.Code)
}
