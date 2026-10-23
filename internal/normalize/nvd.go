package normalize

import (
	"errors"
	"tijeri/internal/models"
)

// DetermineNVDStatus maps feed metadata (e.g. from an NVD JSON payload) to one of the three schema-allowed states.
// Here we simulate the logic based on presence of metrics/analysis.
func DetermineNVDStatus(hasMetrics bool, isLowPriority bool) string {
	if hasMetrics {
		return "full"
	}
	if isLowPriority {
		return "lowest_priority"
	}
	return "not_scheduled"
}

// CheckNVDContradiction verifies the invariant that a finding never has full NVD enrichment but missing CVSS data.
func CheckNVDContradiction(f models.Finding) error {
	if f.NVDEnrichmentStatus == "full" && f.CVSS == nil {
		return errors.New("invariant violation: finding has nvd_enrichment_status=full but cvss=null")
	}
	return nil
}
