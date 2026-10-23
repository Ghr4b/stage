package risk

import (
	"math/rand"
	"testing"
)

func TestCriticalityOverrideProperty(t *testing.T) {
	tiers := []string{"standard", "low_value", "high_value", "mission_critical", "unknown"}
	
	for i := 0; i < 1000; i++ {
		baseDeadline := rand.Intn(100) + 1
		tier := tiers[rand.Intn(len(tiers))]
		
		newDeadline, reason := ApplyCriticalityOverride(baseDeadline, tier)
		
		// Property 1: output_deadline <= base_deadline always holds
		if newDeadline > baseDeadline {
			t.Fatalf("Invariant I8 violated: deadline loosened from %d to %d", baseDeadline, newDeadline)
		}
		
		// Property 2: equality when tier is not high-value/mission-critical
		if tier != "high_value" && tier != "mission_critical" {
			if newDeadline != baseDeadline {
				t.Fatalf("Expected no change for tier %s, got %d from %d", tier, newDeadline, baseDeadline)
			}
			if reason != nil {
				t.Fatalf("Expected nil reason for no change, got %v", *reason)
			}
		}
		
		// Property 3: every non-equal application produces an audit record
		if newDeadline < baseDeadline {
			if reason == nil {
				t.Fatalf("Expected audit record for tightened deadline, got nil")
			}
		}
	}
}
