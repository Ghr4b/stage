package graph

import (
	"context"
	"testing"
)

func TestGUACIngestion(t *testing.T) {
	client := NewMockGUACClient()
	ctx := context.Background()
	
	// P9-1 Integration: fixture SBOM ingested
	client.IngestSBOM(ctx, []byte("fixture-1"))
	client.IngestSBOM(ctx, []byte("fixture-2"))
	
	// Query returns expected source->artifact path
	path1, err := client.QueryBlastRadius(ctx, "CVE-2023-1111")
	if err != nil {
		t.Fatal(err)
	}
	if len(path1) != 1 || path1[0] != "source-repo-1" {
		t.Errorf("Expected source-repo-1, got %v", path1)
	}
	
	path2, err := client.QueryBlastRadius(ctx, "CVE-2024-2222")
	if err != nil {
		t.Fatal(err)
	}
	if len(path2) != 1 || path2[0] != "source-repo-2" {
		t.Errorf("Expected source-repo-2, got %v", path2)
	}
}
