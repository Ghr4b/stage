package cargoaudit

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{"vulnerabilities":{"found":[{"advisory":{"id":"RUSTSEC-2023-0001","package":"hyper"},"versions":{"patched":[">=0.14.27"]},"affected_version":"0.14.25"}]}}`

func TestCargoAuditSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "rust"}}) { t.Error("should support rust") }
	if a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "go"}}) { t.Error("should not support go") }
}

func TestCargoAuditName(t *testing.T) {
	if (&Adapter{}).Name() != "cargo audit" { t.Error("wrong name") }
}

func TestCargoAuditParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 1 { t.Fatalf("expected 1, got %d", len(b.Findings)) }
	if b.Findings[0].VulnerabilityID != "RUSTSEC-2023-0001" { t.Error("wrong vuln id") }
	if b.Findings[0].SourceTool != "cargo audit" { t.Error("wrong source tool") }
}
