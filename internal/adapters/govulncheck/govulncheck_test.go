package govulncheck

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[{"osv":"GO-2023-2102","module":"golang.org/x/net","version":"v0.15.0"}]`

func TestGovulncheckSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "go"}}) { t.Error("should support go") }
	if a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "python"}}) { t.Error("should not support python") }
}

func TestGovulncheckName(t *testing.T) {
	if (&Adapter{}).Name() != "govulncheck" { t.Error("wrong name") }
}

func TestGovulncheckParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 1 { t.Fatalf("expected 1, got %d", len(b.Findings)) }
	if b.Findings[0].VulnerabilityID != "GO-2023-2102" { t.Error("wrong vuln id") }
	if b.Findings[0].SourceTool != "govulncheck" { t.Error("wrong source tool") }
}
