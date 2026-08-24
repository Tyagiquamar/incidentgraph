// Package testdb provides isolated, migration-fresh PostgreSQL databases for
// integration tests. Tests are skipped (not failed) when IG_TEST_DATABASE_URL
// is unset, so `go test ./...` stays green without infrastructure while CI and
// local verification set the variable to run the full suite.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/incidentgraph/incidentgraph/internal/db"
	"github.com/incidentgraph/incidentgraph/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Open creates a uniquely named database (migrations applied) and registers
// cleanup that drops it when the test finishes.
func Open(t *testing.T) *pgxpool.Pool {
	t.Helper()
	base := os.Getenv("IG_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("IG_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	adminURL, err := withDBName(base, "postgres")
	if err != nil {
		t.Fatalf("parse IG_TEST_DATABASE_URL: %v", err)
	}
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	defer admin.Close()

	name := "ig_test_" + strings.ReplaceAll(strings.ToLower(model.New()[:12]), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, name)); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	testURL, err := withDBName(base, name)
	if err != nil {
		t.Fatalf("build test url: %v", err)
	}
	pool, err := db.Connect(ctx, testURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("migrate test database: %v", err)
	}

	dropURL := adminURL
	t.Cleanup(func() {
		pool.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		dpool, err := pgxpool.New(dctx, dropURL)
		if err != nil {
			return
		}
		defer dpool.Close()
		// terminate lingering connections then drop; retry briefly if busy
		for i := 0; i < 10; i++ {
			_, _ = dpool.Exec(dctx,
				`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid <> pg_backend_pid()`, name)
			if _, err := dpool.Exec(dctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, name)); err == nil {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	})
	return pool
}

func withDBName(raw, name string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.Path = "/" + name
	return u.String(), nil
}
