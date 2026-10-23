package graph

import (
	"context"
	"database/sql"
	"testing"
)

func setupDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open sqlite memory db: %v", err)
	}
	if err := InitializeRuntimeDB(db); err != nil {
		t.Fatalf("Failed to init schema: %v", err)
	}
	return db
}

func TestRuntimeRelationshipGraph(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	
	ctx := context.Background()
	
	// Seed data
	db.Exec(`INSERT INTO digests (digest_id, image_name) VALUES ('sha256:111', 'app-v1');`)
	db.Exec(`INSERT INTO hosts (host_id, exposure_level) VALUES ('host-A', 'public');`)
	db.Exec(`INSERT INTO pods (pod_id, digest_id, host_id, status) VALUES ('pod-1', 'sha256:111', 'host-A', 'running');`)
	db.Exec(`INSERT INTO pods (pod_id, digest_id, host_id, status) VALUES ('pod-2-terminated', 'sha256:111', 'host-A', 'terminated');`) // I13 case
	
	results, err := QueryBlastRadiusForDigest(ctx, db, "sha256:111")
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	
	if len(results) != 2 {
		t.Errorf("Expected 2 blast radius records (including terminated), got %d", len(results))
	}
	
	foundTerminated := false
	for _, r := range results {
		if r.PodID == "pod-2-terminated" {
			foundTerminated = true
		}
		if r.Exposure != "public" {
			t.Errorf("Expected exposure 'public', got %s", r.Exposure)
		}
	}
	
	if !foundTerminated {
		t.Error("Expected to find the terminated pod in the blast radius history")
	}
}

// Named test (I13)
func TestImageDigestAsCanonicalAsset(t *testing.T) {
	db := setupDB(t)
	defer db.Close()
	
	ctx := context.Background()
	
	// Digest is canonical
	db.Exec(`INSERT INTO digests (digest_id, image_name) VALUES ('sha256:abc', 'nginx');`)
	db.Exec(`INSERT INTO findings (finding_id, digest_id, cve_id) VALUES ('f1', 'sha256:abc', 'CVE-1');`)
	
	// Pod 1 starts and dies
	db.Exec(`INSERT INTO pods (pod_id, digest_id, host_id, status) VALUES ('pod-1', 'sha256:abc', 'host-A', 'terminated');`)
	
	// We scan history for digest
	history1, _ := GetFindingsForDigest(ctx, db, "sha256:abc")
	if len(history1) != 1 || history1[0] != "CVE-1" {
		t.Errorf("Expected 1 finding for digest, got %v", history1)
	}
	
	// New pod with IDENTICAL digest created
	db.Exec(`INSERT INTO pods (pod_id, digest_id, host_id, status) VALUES ('pod-2', 'sha256:abc', 'host-B', 'running');`)
	
	// Vulnerability history for that digest is unbroken across the transition
	history2, _ := GetFindingsForDigest(ctx, db, "sha256:abc")
	if len(history2) != 1 || history2[0] != "CVE-1" {
		t.Errorf("Expected history to remain identical (1 finding) after pod churn, got %v", history2)
	}
}
