package syft

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{
	"artifacts": [
		{"name": "openssl", "version": "3.1.3", "type": "apk", "purl": "pkg:apk/alpine/openssl@3.1.3"},
		{"name": "busybox", "version": "1.36.1", "type": "apk", "purl": "pkg:apk/alpine/busybox@1.36.1"}
	]
}`

func TestSyftSupportsContainerAssets(t *testing.T) {
	adapter := &Adapter{}
	if !adapter.Supports(models.Asset{Type: "container"}) {
		t.Error("Expected true for container")
	}
	if adapter.Supports(models.Asset{Type: "host"}) {
		t.Error("Expected false for host")
	}
}

func TestSyftName(t *testing.T) {
	if (&Adapter{}).Name() != "syft" {
		t.Error("Expected name 'syft'")
	}
}

func TestSyftParseOutput(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "asset-c-1")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if len(batch.Findings) != 2 {
		t.Fatalf("Expected 2 findings (inventory items), got %d", len(batch.Findings))
	}
	if batch.Findings[0].Component != "openssl" {
		t.Errorf("Expected 'openssl', got %s", batch.Findings[0].Component)
	}
	if batch.Findings[0].SourceTool != "syft" {
		t.Errorf("Expected source_tool 'syft', got %s", batch.Findings[0].SourceTool)
	}
}
