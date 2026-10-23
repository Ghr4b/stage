package defectdojo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"tijeri/internal/models"
)

func TestDefectDojoIntegration(t *testing.T) {
	// Mock DefectDojo API
	store := make(map[int]DefectDojoFinding)
	nextID := 1
	
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/api/v2/findings/" {
			var f DefectDojoFinding
			if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.ID = nextID
			store[nextID] = f
			nextID++
			
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(f)
			return
		}
		
		if r.Method == "GET" {
			// Extract ID from path, e.g. /api/v2/findings/1/
			var id int
			_, err := fmt.Sscanf(r.URL.Path, "/api/v2/findings/%d/", &id)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			
			f, ok := store[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(f)
			return
		}
		
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, "dummy-token")
	
	// Prepare fixture finding
	f := models.Finding{
		AssetID:         "asset-team-a",
		SourceTool:      "govulncheck",
		VulnerabilityID: "CVE-2023-1234",
		Component:       "package-xyz",
		CVSS:            &models.CVSS{Score: 8.5},
		DedupHash:       "hash-123",
	}
	
	ctx := context.Background()
	
	// Push finding
	id, err := client.PushFinding(ctx, f, 42)
	if err != nil {
		t.Fatalf("Failed to push finding: %v", err)
	}
	
	// Verify it's retrievable
	retrieved, err := client.GetFinding(ctx, id)
	if err != nil {
		t.Fatalf("Failed to get finding: %v", err)
	}
	
	if retrieved.UniqueIdFromTool != f.DedupHash {
		t.Errorf("Expected DedupHash %s, got %s", f.DedupHash, retrieved.UniqueIdFromTool)
	}
}
