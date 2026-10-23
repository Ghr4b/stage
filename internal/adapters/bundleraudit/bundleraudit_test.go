package bundleraudit

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[{"advisory":"CVE-2023-22796","gem":"activesupport","version":"7.0.4"}]`

func TestBundlerAuditSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "ruby"}}) { t.Error("should support ruby") }
	if a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "node"}}) { t.Error("should not support node") }
}

func TestBundlerAuditName(t *testing.T) {
	if (&Adapter{}).Name() != "bundler-audit" { t.Error("wrong name") }
}

func TestBundlerAuditParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 1 { t.Fatalf("expected 1, got %d", len(b.Findings)) }
	if b.Findings[0].Component != "activesupport" { t.Error("wrong component") }
	if b.Findings[0].SourceTool != "bundler-audit" { t.Error("wrong source tool") }
}
