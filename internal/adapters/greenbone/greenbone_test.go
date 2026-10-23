package greenbone

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[
	{
		"nvt": "1.3.6.1.4.1.25623.1.0.100315",
		"name": "Apache HTTP Server Version Detection",
		"host": "192.168.1.10",
		"port": "80/tcp",
		"severity": "high",
		"cve_id": "CVE-2023-25690",
		"component": "apache-httpd",
		"version": "2.4.49"
	},
	{
		"nvt": "1.3.6.1.4.1.25623.1.0.100220",
		"name": "OpenSSH Vulnerability",
		"host": "192.168.1.10",
		"port": "22/tcp",
		"severity": "medium",
		"cve_id": "CVE-2023-38408",
		"component": "openssh",
		"version": "8.9p1"
	}
]`

func TestGreenboneSupportsOnlyHosts(t *testing.T) {
	adapter := &Adapter{}

	if !adapter.Supports(models.Asset{Type: "host"}) {
		t.Error("Expected Supports() to return true for host assets")
	}
	if adapter.Supports(models.Asset{Type: "repo"}) {
		t.Error("Expected Supports() to return false for repo assets")
	}
	if adapter.Supports(models.Asset{Type: "container"}) {
		t.Error("Expected Supports() to return false for container assets")
	}
}

func TestGreenbneName(t *testing.T) {
	adapter := &Adapter{}
	if adapter.Name() != "greenbone" {
		t.Errorf("Expected name 'greenbone', got %s", adapter.Name())
	}
}

func TestGreenboneParseOutput(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "asset-host-1")
	if err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}

	if len(batch.Findings) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(batch.Findings))
	}

	f1 := batch.Findings[0]
	if f1.VulnerabilityID != "CVE-2023-25690" {
		t.Errorf("Expected CVE-2023-25690, got %s", f1.VulnerabilityID)
	}
	if f1.SourceTool != "greenbone" {
		t.Errorf("Expected source_tool 'greenbone', got %s", f1.SourceTool)
	}
	if f1.Component != "apache-httpd" {
		t.Errorf("Expected component 'apache-httpd', got %s", f1.Component)
	}

	f2 := batch.Findings[1]
	if f2.VulnerabilityID != "CVE-2023-38408" {
		t.Errorf("Expected CVE-2023-38408, got %s", f2.VulnerabilityID)
	}
}
