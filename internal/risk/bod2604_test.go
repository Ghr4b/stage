package risk

import (
	"testing"
)

// Named test (I7)
func TestBod2604MatchesCisaPublishedTable(t *testing.T) {
	bTrue := true
	bFalse := false

	tests := []struct {
		exposure    *bool
		kev         bool
		automatable *bool
		techImpact  bool
		expected    int
	}{
		// KEV = true
		{&bTrue, true, &bTrue, true, 3},
		{&bTrue, true, &bTrue, false, 7},
		{&bTrue, true, &bFalse, true, 7},
		{&bTrue, true, &bFalse, false, 14},
		{&bFalse, true, &bTrue, true, 14},
		{&bFalse, true, &bTrue, false, 30},
		{&bFalse, true, &bFalse, true, 30},
		{&bFalse, true, &bFalse, false, 30},

		// KEV = false
		{&bTrue, false, &bTrue, true, 30},
		{&bTrue, false, &bTrue, false, 30},
		{&bTrue, false, &bFalse, true, 90},
		{&bTrue, false, &bFalse, false, 90},
		{&bFalse, false, &bTrue, true, 90},
		{&bFalse, false, &bTrue, false, 90},
		{&bFalse, false, &bFalse, true, 90},
		{&bFalse, false, &bFalse, false, 90},
	}

	for i, tc := range tests {
		result := CalculateBOD2604Deadline(tc.exposure, tc.kev, tc.automatable, tc.techImpact)
		if result != tc.expected {
			t.Errorf("Combination %d failed: expected %d, got %d", i, tc.expected, result)
		}
	}
}

func TestMissingExposureDefaultsToPublic(t *testing.T) {
	bTrue := true
	
	// If exposure is nil, it defaults to true.
	// KEV=true, exposure=nil (true), auto=true, tech=true -> 3
	// KEV=true, exposure=false, auto=true, tech=true -> 14
	result := CalculateBOD2604Deadline(nil, true, &bTrue, true)
	if result != 3 {
		t.Errorf("Expected nil exposure to default to public (true) and yield 3, got %d", result)
	}
}

func TestMissingAutomatabilityDefaultsToAutomatable(t *testing.T) {
	bTrue := true
	
	// If automatable is nil, it defaults to true.
	// KEV=true, exposure=true, auto=nil (true), tech=false -> 7
	// KEV=true, exposure=true, auto=false, tech=false -> 14
	result := CalculateBOD2604Deadline(&bTrue, true, nil, false)
	if result != 7 {
		t.Errorf("Expected nil automatability to default to true and yield 7, got %d", result)
	}
}
