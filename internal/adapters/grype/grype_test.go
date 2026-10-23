package grype

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{
	"matches": [
		{
			"vulnerability": {"id": "CVE-2023-44487", "severity": "High"},
			"artifact": {"name": "golang.org/x/net", "version": "v0.15.0"}
		},
		{
			"vulnerability": {"id": "CVE-2023-39325", "severity": "High"},
			"artifact": {"name": "golang.org/x/net", "version": "v0.15.0"}
		}
	]
}`

func TestGrypeSupportsContainerAssets(t *testing.T) {
	adapter := &Adapter{}
	if !adapter.Supports(models.Asset{Type: "container"}) {
		t.Error("Expected true for container")
	}
	if adapter.Supports(models.Asset{Type: "host"}) {
		t.Error("Expected false for host")
	}
}

func TestGrypeName(t *testing.T) {
	if (&Adapter{}).Name() != "grype" {
		t.Error("Expected name 'grype'")
	}
}

func TestGrypeParseOutput(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "asset-c-1")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(batch.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(batch.Findings))
	}
	if batch.Findings[0].VulnerabilityID != "CVE-2023-44487" {
		t.Errorf("Wrong vuln ID: %s", batch.Findings[0].VulnerabilityID)
	}
	if batch.Findings[0].SourceTool != "grype" {
		t.Errorf("Wrong source tool: %s", batch.Findings[0].SourceTool)
	}
}
