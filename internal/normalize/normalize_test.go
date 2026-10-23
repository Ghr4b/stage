package normalize

import (
	"testing"
	"tijeri/internal/models"
	
	"tijeri/internal/adapters/greenbone"
	"tijeri/internal/adapters/nuclei"
	"tijeri/internal/adapters/trivy"
	"tijeri/internal/adapters/grype"
	"tijeri/internal/adapters/syft"
	"tijeri/internal/adapters/uvaudit"
	"tijeri/internal/adapters/govulncheck"
	"tijeri/internal/adapters/npmaudit"
	"tijeri/internal/adapters/cargoaudit"
	"tijeri/internal/adapters/bundleraudit"
	"tijeri/internal/adapters/osvscanner"
	"tijeri/internal/adapters/gitleaks"
)

func fillRequiredFields(f *models.Finding) {
	if f.FindingID == "" { f.FindingID = "test-id" }
	if f.NVDEnrichmentStatus == "" { f.NVDEnrichmentStatus = "not_scheduled" }
	if f.EPSS == nil { f.EPSS = &models.EPSS{Score: 0.0, Percentile: 0.0} }
	if f.DedupHash == "" { f.DedupHash = "test-hash" }
}

func testAdapterOutput(t *testing.T, adapterName string, parseFunc func([]byte, string) (models.FindingsBatch, error), fixture []byte) {
	t.Run(adapterName, func(t *testing.T) {
		batch, err := parseFunc(fixture, "asset-1")
		if err != nil {
			t.Fatalf("Failed to parse fixture: %v", err)
		}
		
		for i, f := range batch.Findings {
			fillRequiredFields(&f)
			if err := ValidateFinding("../../schemas/finding.schema.json", f); err != nil {
				t.Errorf("Finding %d failed schema validation: %v", i, err)
			}
		}
	})
}

func TestPerAdapterNormalizers(t *testing.T) {
	// Greenbone
	testAdapterOutput(t, "greenbone", greenbone.ParseOutput, []byte(`[{"nvt":"1","name":"A","host":"H","port":"80","severity":"high","cve_id":"CVE-1","component":"C","version":"1"}]`))
	
	// Nuclei
	testAdapterOutput(t, "nuclei", nuclei.ParseOutput, []byte(`[{"template-id":"1","info":{"name":"A","severity":"high"},"host":"H","ip":"1","port":"80"}]`))
	
	// Trivy
	testAdapterOutput(t, "trivy", trivy.ParseOutput, []byte(`[{"Target":"T","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"P","InstalledVersion":"1","Severity":"HIGH"}]}]`))
	
	// Grype
	testAdapterOutput(t, "grype", grype.ParseOutput, []byte(`{"matches":[{"vulnerability":{"id":"CVE-1","severity":"High"},"artifact":{"name":"P","version":"1"}}]}`))
	
	// Syft
	testAdapterOutput(t, "syft", syft.ParseOutput, []byte(`{"artifacts":[{"name":"P","version":"1","type":"apk","purl":"pkg"}]}`))
	
	// UV Audit
	testAdapterOutput(t, "uvaudit", uvaudit.ParseOutput, []byte(`[{"id":"1","package":"P","installed_version":"1"}]`))
	
	// Govulncheck
	testAdapterOutput(t, "govulncheck", govulncheck.ParseOutput, []byte(`[{"osv":"1","module":"P","version":"1"}]`))
	
	// NPM Audit
	testAdapterOutput(t, "npmaudit", npmaudit.ParseOutput, []byte(`{"advisories":{"1":{"id":1,"module_name":"P","findings_version":"1","severity":"high","cves":"CVE-1"}}}`))
	
	// Cargo Audit
	testAdapterOutput(t, "cargoaudit", cargoaudit.ParseOutput, []byte(`{"vulnerabilities":{"found":[{"advisory":{"id":"1","package":"P"},"versions":{"patched":["2"]},"affected_version":"1"}]}}`))
	
	// Bundler Audit
	testAdapterOutput(t, "bundleraudit", bundleraudit.ParseOutput, []byte(`[{"advisory":"1","gem":"P","version":"1"}]`))
	
	// OSV Scanner
	testAdapterOutput(t, "osvscanner", osvscanner.ParseOutput, []byte(`{"results":[{"id":"1","package":{"name":"P","version":"1","ecosystem":"E"}}]}`))
	
	// Gitleaks
	testAdapterOutput(t, "gitleaks", gitleaks.ParseOutput, []byte(`[{"Description":"D","Match":"M","Secret":"S","File":"F","RuleID":"1"}]`))
}
