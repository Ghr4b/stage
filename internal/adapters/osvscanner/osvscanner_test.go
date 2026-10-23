package osvscanner

import (
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `{"results":[{"id":"GHSA-xxxx-yyyy-zzzz","package":{"name":"express","version":"4.17.1","ecosystem":"npm"}},{"id":"GO-2023-2102","package":{"name":"golang.org/x/net","version":"v0.15.0","ecosystem":"Go"}}]}`

func TestOSVScannerSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Type: "repo"}) { t.Error("should support repo") }
	if a.Supports(models.Asset{Type: "host"}) { t.Error("should not support host") }
}

func TestOSVScannerName(t *testing.T) {
	if (&Adapter{}).Name() != "osv-scanner" { t.Error("wrong name") }
}

func TestOSVScannerParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil { t.Fatal(err) }
	if len(b.Findings) != 2 { t.Fatalf("expected 2, got %d", len(b.Findings)) }
	if b.Findings[0].VulnerabilityID != "GHSA-xxxx-yyyy-zzzz" { t.Error("wrong vuln id") }
	if b.Findings[1].VulnerabilityID != "GO-2023-2102" { t.Error("wrong vuln id for 2nd") }
	if b.Findings[0].SourceTool != "osv-scanner" { t.Error("wrong source tool") }
}
