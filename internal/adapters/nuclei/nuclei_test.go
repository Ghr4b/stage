package nuclei

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{"template-id":"apache-detect","info":{"name":"Apache Detection","severity":"info"},"host":"192.168.1.10","ip":"192.168.1.10","port":"80"}
{"template-id":"cve-2023-25690","info":{"name":"Apache HTTP Request Smuggling","severity":"critical"},"host":"192.168.1.10","ip":"192.168.1.10","port":"80","cve-id":"CVE-2023-25690"}`

func TestNucleiSupportsOnlyHosts(t *testing.T) {
	adapter := &Adapter{}

	if !adapter.Supports(models.Asset{Type: "host"}) {
		t.Error("Expected Supports() to return true for host assets")
	}
	if adapter.Supports(models.Asset{Type: "repo"}) {
		t.Error("Expected Supports() to return false for repo assets")
	}
}

func TestNucleiName(t *testing.T) {
	adapter := &Adapter{}
	if adapter.Name() != "nuclei" {
		t.Errorf("Expected name 'nuclei', got %s", adapter.Name())
	}
}

func TestNucleiParseOutput(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "asset-host-1")
	if err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}

	if len(batch.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(batch.Findings))
	}

	// First finding uses template-id as vuln ID (no CVE)
	f1 := batch.Findings[0]
	if f1.VulnerabilityID != "apache-detect" {
		t.Errorf("Expected 'apache-detect' as vuln ID, got %s", f1.VulnerabilityID)
	}

	// Second finding uses CVE ID
	f2 := batch.Findings[1]
	if f2.VulnerabilityID != "CVE-2023-25690" {
		t.Errorf("Expected CVE-2023-25690, got %s", f2.VulnerabilityID)
	}
	if f2.SourceTool != "nuclei" {
		t.Errorf("Expected source_tool 'nuclei', got %s", f2.SourceTool)
	}
}
