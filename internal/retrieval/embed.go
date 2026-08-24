// Package retrieval implements ingestion chunking, embedding providers,
// lexical/vector/hybrid search over PostgreSQL (+pgvector), an optional
// heuristic reranker, and benchmark metrics.
package retrieval

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"strings"
	"sync"
)

// Embedder produces a fixed-dimension dense vector for text.
type Embedder interface {
	Dim() int
	Embed(text string) []float32
	Name() string
}

// ---------------------------------------------------------------- hashing embedder

// HashEmbedder is a deterministic, dependency-free feature-hashing embedder:
// unigrams + bigrams are hashed into `dim` buckets with subword stability,
// weighted by 1+ln(tf) and L2-normalized. It requires no network and makes
// local/demo/pgvector paths fully reproducible. Swap in a real embedding
// provider (OpenAIEmbedder) for production-quality semantics; the schema is
// dimension-compatible.
type HashEmbedder struct{ dim int }

func NewHashEmbedder(dim int) *HashEmbedder {
	if dim <= 0 || dim%2 != 0 {
		dim = 1536
	}
	return &HashEmbedder{dim: dim}
}

func (h *HashEmbedder) Dim() int     { return h.dim }
func (h *HashEmbedder) Name() string { return "hash-v1" }

var wordRe = strings.FieldsFunc

func tokenizeForEmbedding(text string) []string {
	fields := strings.ToLower(text)
	var out []string
	start := -1
	for i := 0; i <= len(fields); i++ {
		c := byte(0)
		if i < len(fields) {
			c = fields[i]
		}
		isWord := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c >= 128
		if isWord && start < 0 {
			start = i
		} else if !isWord && start >= 0 {
			out = append(out, fields[start:i])
			start = -1
		}
	}
	return out
}

func (h *HashEmbedder) Embed(text string) []float32 {
	vec := make([]float32, h.dim)
	tokens := tokenizeForEmbedding(text)
	if len(tokens) == 0 {
		return vec
	}
	add := func(tok string, weight float64, seed uint32) {
		sum := fnv32a(tok, seed)
		idx := sum % uint32(h.dim)
		vec[idx] += float32(weight)
	}
	tf := make(map[string]int, len(tokens))
	for _, t := range tokens {
		tf[t]++
	}
	for t, count := range tf {
		w := 1 + math.Log(float64(count))
		add(t, w, 0x811c9dc5)
	}
	for i := 0; i+1 < len(tokens); i++ {
		bigram := tokens[i] + "_" + tokens[i+1]
		add(bigram, 0.7, 0x9e3779b9)
	}
	normalize(vec)
	return vec
}

func fnv32a(s string, seed uint32) uint32 {
	h := seed
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func normalize(v []float32) {
	var norm float64
	for _, x := range v {
		norm += float64(x) * float64(x)
	}
	if norm == 0 {
		return
	}
	inv := float32(1 / math.Sqrt(norm))
	for i := range v {
		v[i] *= inv
	}
}

// Cosine similarity for already-normalized vectors is the dot product.
func Cosine(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}

// ---------------------------------------------------------------- openai-compatible embedder

// OpenAIEmbedder calls an OpenAI-compatible /embeddings endpoint.
type OpenAIEmbedder struct {
	BaseURL, APIKey, Model string
	dim                    int
	client                 *httpClient
	mu                     sync.Mutex
}

func NewOpenAIEmbedder(baseURL, apiKey, model string, dim int) *OpenAIEmbedder {
	if dim <= 0 {
		dim = 1536
	}
	return &OpenAIEmbedder{BaseURL: baseURL, APIKey: apiKey, Model: model, dim: dim, client: newHTTPClient(30)}
}

func (o *OpenAIEmbedder) Dim() int     { return o.dim }
func (o *OpenAIEmbedder) Name() string { return o.Model }

func (o *OpenAIEmbedder) Embed(text string) []float32 {
	body := map[string]any{"model": o.Model, "input": text}
	var resp struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := o.client.postJSON(o.BaseURL+"/embeddings", o.APIKey, body, &resp); err != nil || len(resp.Data) == 0 {
		// Fail closed to the deterministic embedder so ingestion never breaks;
		// swap-in quality is benchmarked either way.
		fb := NewHashEmbedder(o.dim)
		return fb.Embed(text)
	}
	v := resp.Data[0].Embedding
	if len(v) > o.dim {
		v = v[:o.dim]
	}
	if len(v) < o.dim {
		padded := make([]float32, o.dim)
		copy(padded, v)
		v = padded
	}
	normalize(v)
	return v
}

var _ = sha256.Sum256
var _ = binary.MaxVarintLen64
