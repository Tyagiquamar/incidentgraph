# Checkout Service Runbook

## Normal operation
Checkout serves cart checkout flows with p99 under 300ms.
Database connection pool is sized by POOL_SIZE (recommended 40).
Redis caches product catalog entries with 15m TTL.

## Database checks
Watch `db_wait_ms` and `pool_exhausted_total` metrics.
If acquire timeouts appear, inspect recent deployments for pool config changes:
connection pool regressions typically show DB wait climbing while CPU stays flat.

## Rollback procedure
1. Revert the deployment commit (see get_git_diff for the suspect commit).
2. Restore POOL_SIZE to 40.
3. Redeploy and confirm db_wait_ms returns to baseline within 5 minutes.

## Escalation
Page the database on-call if primary connections stay above 90% utilization.
