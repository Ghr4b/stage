package remediation

import (
	"strings"
	"testing"
	"tijeri/internal/models"
	"tijeri/internal/risk"
)

func TestPopulateTicket(t *testing.T) {
	f := models.Finding{
		VulnerabilityID:  "CVE-2023-1234",
		Component:        "log4j",
		ComponentVersion: "2.14.0",
		KEVListed:        true,
		EPSS:             &models.EPSS{Score: 0.95},
	}
	
	riskOutput := risk.ExplainabilityOutput{
		BODTier:    14,
		SSVCBucket: "act",
	}
	
	owner := "platform-team"
	fix := "2.17.1"
	
	payload := PopulateTicket(owner, f, riskOutput, fix)
	
	if payload.Owner != owner || payload.VulnerabilityID != f.VulnerabilityID || 
	   payload.Component != f.Component || payload.Version != f.ComponentVersion || 
	   payload.FixVersion != fix || payload.KEVListed != f.KEVListed || 
	   payload.EPSSScore != f.EPSS.Score || payload.SSVCBucket != riskOutput.SSVCBucket || 
	   payload.BODTierDeadline != riskOutput.BODTier {
		t.Errorf("One or more fields failed to populate correctly: %+v", payload)
	}
	
	desc := GenerateTicketDescription(payload)
	expectedFragments := []string{
		"Vulnerability: CVE-2023-1234",
		"Component: log4j@2.14.0",
		"Suggested Fix: 2.17.1",
		"Owner: platform-team",
		"KEV Listed: true",
		"EPSS Score: 0.95",
		"SSVC Bucket: act",
		"BOD 26-04 SLA Deadline: 14 days",
	}
	
	for _, frag := range expectedFragments {
		if !strings.Contains(desc, frag) {
			t.Errorf("Expected description to contain %q, but it didn't.\nGot:\n%s", frag, desc)
		}
	}
}
