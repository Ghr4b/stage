package remediation

import (
	"testing"
)

func TestSLAComputationFromRiskEngine(t *testing.T) {
	bTrue := true
	bFalse := false
	
	// Finding 1: Highly critical, exposed, KEV -> shorter SLA
	sla1 := ComputeSLA(&bTrue, true, &bTrue, true, "mission_critical")
	
	// Finding 2: Same technical vulnerability internally, not KEV, low criticality
	sla2 := ComputeSLA(&bFalse, false, &bTrue, true, "low_value")
	
	if sla1 == sla2 {
		t.Errorf("Regression: SLA should not be a flat rule. Expected different SLAs for different risk contexts, but got %d for both", sla1)
	}
	
	if sla1 >= sla2 {
		t.Errorf("Expected mission-critical/exposed/KEV to have a shorter SLA than low-value/internal/not-KEV. Got %d vs %d", sla1, sla2)
	}
}
