# Retrieval Benchmark

> Populated from an actual benchmark run — never hand-edited.

- Queries: 55 (datasets/retrieval/queries.json)
- Corpus: synthetic incident corpora ingested via cmd/seed
- Embedder: hash-v1 (dim 1536)
- Date: 2026-08-23T19:27:05Z

| Mode | Recall@5 | Recall@10 | MRR | p50 (ms) | p95 (ms) |
|------|----------|-----------|-----|----------|----------|
| lexical | 0.306 | 0.306 | 0.409 | 0.5 | 0.8 |
| vector | 0.870 | 0.961 | 0.818 | 0.9 | 1.6 |
| hybrid | 0.879 | 0.961 | 0.874 | 1.3 | 2.1 |
| rerank | 0.952 | 0.976 | 0.933 | 1.3 | 2.4 |

Hybrid scoring: combined = 0.45*lex_norm + 0.55*cos_sim where lex_norm = ts_rank/(ts_rank+1). See internal/retrieval/store.go.
