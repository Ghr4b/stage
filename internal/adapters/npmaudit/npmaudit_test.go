package npmaudit

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{"advisories":{"1":{"id":1,"module_name":"lodash","findings_version":"4.17.20","severity":"high","cves":"CVE-2021-23337"}}}`

func TestNpmAuditSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "node"}}) { t.Error("should support node") }
	if a.Supports(models.Asset{Metadata: map[string]string{"ecosystems": "python"}}) { t.Error("should not support python") }
}

func TestNpmAuditName(t *testing.T) {
	if (&Adapter{}).Name() != "npm audit" { t.Error("wrong name") }
}

func TestNpmAuditParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 1 { t.Fatalf("expected 1, got %d", len(b.Findings)) }
	if b.Findings[0].Component != "lodash" { t.Error("wrong component") }
	if b.Findings[0].SourceTool != "npm audit" { t.Error("wrong source tool") }
}
