package remediation

import (
	"fmt"
	"tijeri/internal/models"
	"tijeri/internal/risk"
)

type TicketPayload struct {
	Owner           string
	VulnerabilityID string
	Component       string
	Version         string
	FixVersion      string
	KEVListed       bool
	EPSSScore       float64
	SSVCBucket      string
	BODTierDeadline int
}

// PopulateTicket generates a structured payload for a ticketing system,
// ensuring all required enrichment fields are mapped.
func PopulateTicket(owner string, f models.Finding, riskOutput risk.ExplainabilityOutput, suggestedFix string) TicketPayload {
	var epss float64
	if f.EPSS != nil {
		epss = f.EPSS.Score
	}
	
	return TicketPayload{
		Owner:           owner,
		VulnerabilityID: f.VulnerabilityID,
		Component:       f.Component,
		Version:         f.ComponentVersion,
		FixVersion:      suggestedFix,
		KEVListed:       f.KEVListed,
		EPSSScore:       epss,
		SSVCBucket:      riskOutput.SSVCBucket,
		BODTierDeadline: riskOutput.BODTier,
	}
}

// GenerateTicketDescription creates a human-readable text block for the ticket body.
func GenerateTicketDescription(payload TicketPayload) string {
	return fmt.Sprintf(`Vulnerability: %s
Component: %s@%s
Suggested Fix: %s
Owner: %s

Risk Context:
- KEV Listed: %t
- EPSS Score: %.2f
- SSVC Bucket: %s
- BOD 26-04 SLA Deadline: %d days
`, payload.VulnerabilityID, payload.Component, payload.Version, payload.FixVersion, payload.Owner, payload.KEVListed, payload.EPSSScore, payload.SSVCBucket, payload.BODTierDeadline)
}
