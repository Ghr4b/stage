package risk

import "fmt"

// ApplyCriticalityOverride applies the Step 2 criticality override to a base deadline.
// It enforces I8: Criticality override can only tighten a deadline, never loosen one.
// Returns the new deadline and an audit reason if an override was applied.
func ApplyCriticalityOverride(baseDeadline int, criticalityTier string) (int, *string) {
	if criticalityTier == "mission_critical" {
		newDeadline := baseDeadline / 2
		if newDeadline < 1 {
			newDeadline = 1
		}
		reason := fmt.Sprintf("Tightened from %d to %d due to mission_critical tier", baseDeadline, newDeadline)
		return newDeadline, &reason
	}
	
	if criticalityTier == "high_value" {
		newDeadline := baseDeadline * 3 / 4
		if newDeadline < 1 {
			newDeadline = 1
		}
		reason := fmt.Sprintf("Tightened from %d to %d due to high_value tier", baseDeadline, newDeadline)
		return newDeadline, &reason
	}
	
	return baseDeadline, nil
}
