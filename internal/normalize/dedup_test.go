package normalize

import (
	"strings"
	"testing"
	"tijeri/internal/models"
)

func TestGenerateDedupHash(t *testing.T) {
	f1 := models.Finding{
		AssetID:         "asset-1",
		VulnerabilityID: "CVE-2023-1234",
		Component:       "package-a",
	}
	f2 := models.Finding{
		AssetID:         "asset-1",
		VulnerabilityID: "CVE-2023-1234",
		Component:       "package-a",
	}
	f3 := models.Finding{
		AssetID:         "asset-2",
		VulnerabilityID: "CVE-2023-1234",
		Component:       "package-a",
	}
	
	h1 := GenerateDedupHash(f1)
	h2 := GenerateDedupHash(f2)
	h3 := GenerateDedupHash(f3)
	
	if h1 != h2 {
		t.Errorf("Expected identical inputs to produce identical hashes, got %s and %s", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("Expected different inputs to produce different hashes, got identical %s", h1)
	}
}

// Named test exactly as requested in P4-5 acceptance criteria
func TestDedupCollapsesGovulncheckAndOSVScannerSameFinding(t *testing.T) {
	findings := []models.Finding{
		{
			FindingID:       "id-1",
			AssetID:         "asset-1",
			VulnerabilityID: "CVE-2023-1234",
			Component:       "github.com/gin-gonic/gin",
			SourceTool:      "govulncheck",
		},
		{
			FindingID:       "id-2",
			AssetID:         "asset-1",
			VulnerabilityID: "CVE-2023-1234",
			Component:       "github.com/gin-gonic/gin",
			SourceTool:      "osv-scanner",
		},
	}
	
	deduped := DedupFindings(findings)
	
	if len(deduped) != 1 {
		t.Fatalf("Expected 1 deduped finding, got %d", len(deduped))
	}
	
	tools := deduped[0].SourceTool
	if !strings.Contains(tools, "govulncheck") || !strings.Contains(tools, "osv-scanner") {
		t.Errorf("Expected combined SourceTool to contain both 'govulncheck' and 'osv-scanner', got '%s'", tools)
	}
}
