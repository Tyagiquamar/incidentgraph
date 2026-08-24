# Orders Query Patterns

## Known anti-patterns
N+1 select loops are forbidden in list endpoints: one query per item multiplies DB load.
Batch item fetches with a single IN (...) query.

## Diagnosis
If order-history latency grows with item count while cache hit rate stays normal,
inspect request logs for repeated SELECT ... FROM order_items per request.
