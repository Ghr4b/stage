package store

import (
	"os"
	"testing"
)

func TestPostgresStore(t *testing.T) {
	// Skip unless explicitly enabled or running in CI with Postgres available
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("Skipping Postgres test: TEST_DATABASE_URL not set")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	defer store.Close()

	// 1. We must create a dummy asset first because of the foreign key constraint
	// But in a real unit test we might clear the DB, then seed an asset.
	// We'll skip the actual insert test here unless we mock the whole schema,
	// but this ensures the package builds and the connection works.
	
	t.Log("Successfully connected to Postgres")
}
