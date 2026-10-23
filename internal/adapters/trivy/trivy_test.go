package trivy

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[
	{
		"Target": "alpine:3.18 (alpine 3.18.4)",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2023-5678",
				"PkgName": "openssl",
				"InstalledVersion": "3.1.3-r0",
				"Severity": "MEDIUM"
			},
			{
				"VulnerabilityID": "CVE-2023-6129",
				"PkgName": "openssl",
				"InstalledVersion": "3.1.3-r0",
				"Severity": "LOW"
			}
		]
	}
]`

func TestTrivySupportsContainerAssets(t *testing.T) {
	adapter := &Adapter{}

	if !adapter.Supports(models.Asset{Type: "container"}) {
		t.Error("Expected Supports() to return true for container assets")
	}
	if !adapter.Supports(models.Asset{Type: "repo", Metadata: map[string]string{"ecosystems": "docker"}}) {
		t.Error("Expected Supports() to return true for assets with docker ecosystem")
	}
	if adapter.Supports(models.Asset{Type: "host"}) {
		t.Error("Expected Supports() to return false for host assets")
	}
}

func TestTrivyName(t *testing.T) {
	adapter := &Adapter{}
	if adapter.Name() != "trivy" {
		t.Errorf("Expected name 'trivy', got %s", adapter.Name())
	}
}

func TestTrivyParseOutput(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "asset-container-1")
	if err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}

	if len(batch.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(batch.Findings))
	}

	f := batch.Findings[0]
	if f.VulnerabilityID != "CVE-2023-5678" {
		t.Errorf("Expected CVE-2023-5678, got %s", f.VulnerabilityID)
	}
	if f.Component != "openssl" {
		t.Errorf("Expected component 'openssl', got %s", f.Component)
	}
	if f.SourceTool != "trivy" {
		t.Errorf("Expected source_tool 'trivy', got %s", f.SourceTool)
	}
}

func TestTrivyVEXConfig(t *testing.T) {
	adapter := &Adapter{Config: Config{VEXEnabled: true, VEXPath: "/path/to/vex.json"}}
	if !adapter.Config.VEXEnabled {
		t.Error("Expected VEX to be enabled")
	}
	if adapter.Config.VEXPath != "/path/to/vex.json" {
		t.Error("Expected VEX path to be set")
	}
}
