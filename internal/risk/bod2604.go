package risk

// CalculateBOD2604Deadline takes four boolean variables (some nullable for missing inputs)
// and returns a remediation deadline in days based on the CISA BOD 26-04 table.
// Returns an integer representing days (e.g., 3, 14, 30, 90).
func CalculateBOD2604Deadline(exposure *bool, kev bool, automatable *bool, techImpact bool) int {
	// P5-2: Fail-safe conservative defaults
	// Unresolved exposure defaults to true (publicly exposed)
	var isExposed bool
	if exposure == nil {
		isExposed = true
	} else {
		isExposed = *exposure
	}

	// Unresolved automatability defaults to true (automatable)
	var isAutomatable bool
	if automatable == nil {
		isAutomatable = true
	} else {
		isAutomatable = *automatable
	}

	// 16 combinations mapped to deadlines (simulated CISA BOD 26-04 table)
	if kev {
		if isExposed {
			if isAutomatable {
				if techImpact {
					return 3 // KEV, Exposed, Auto, TechImpact (Full) -> 3 days
				}
				return 7 // KEV, Exposed, Auto, Partial -> 7 days
			}
			if techImpact {
				return 7 // KEV, Exposed, NotAuto, Full -> 7 days
			}
			return 14 // KEV, Exposed, NotAuto, Partial -> 14 days
		}
		// Not exposed but KEV
		if isAutomatable {
			if techImpact {
				return 14
			}
			return 30
		}
		if techImpact {
			return 30
		}
		return 30
	}

	// Not KEV
	if isExposed {
		if isAutomatable {
			if techImpact {
				return 30
			}
			return 30
		}
		if techImpact {
			return 90
		}
		return 90
	}
	
	// Not KEV, Not Exposed
	return 90 // Fix on upgrade
}
