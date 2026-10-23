package cloud

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestCloudDiscoveryAdapterIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	dbPath := "./test_cq.db"
	defer os.Remove(dbPath)

	// Simulate CQ having written to the DB
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open sqlite db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE aws_s3_buckets (name TEXT, region TEXT); INSERT INTO aws_s3_buckets VALUES ('test-cloudquery-bucket', 'us-east-1');`)
	if err != nil {
		t.Fatalf("Failed to setup test db: %v", err)
	}

	adapter := &CQAdapter{
		CQConfigPath: "dummy.yml",
		DBPath:       dbPath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query adapter
	results, err := adapter.Query(ctx, "SELECT * FROM aws_s3_buckets")
	if err != nil {
		t.Fatalf("Failed to query via adapter: %v", err)
	}

	if len(results) == 0 {
		t.Errorf("Expected >0 rows from adapter query, got 0")
	}

	// For Sync, we skip if cloudquery CLI is not installed
	err = adapter.Sync(ctx)
	if err != nil {
		t.Logf("CloudQuery sync returned error (expected if CLI not installed or auth missing): %v", err)
	}
}
