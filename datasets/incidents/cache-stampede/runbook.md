# Checkout Caching Guide

## TTL strategy
Product catalog entries use 15m TTL. Stagger TTLs with jitter to avoid
synchronized expiration. A synchronized expiry wave causes a stampede:
cache miss storm overloads the backing store (thundering herd).

## Signals
- cache miss rate spikes at fixed intervals
- backing store load inversely mirrors redis evict/miss metrics
