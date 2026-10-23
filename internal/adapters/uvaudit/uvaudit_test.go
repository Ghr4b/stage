package uvaudit

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[{"id":"PYSEC-2023-001","package":"requests","installed_version":"2.28.0"}]`

func TestUvAuditSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "python"}}) { t.Error("should support python") }
	if a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "go"}}) { t.Error("should not support go") }
}

func TestUvAuditName(t *testing.T) {
	if (&Adapter{}).Name() != "uv audit" { t.Error("wrong name") }
}

func TestUvAuditParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 1 { t.Fatalf("expected 1, got %d", len(b.Findings)) }
	if b.Findings[0].VulnerabilityID != "PYSEC-2023-001" { t.Error("wrong vuln id") }
	if b.Findings[0].SourceTool != "uv audit" { t.Error("wrong source tool") }
}
