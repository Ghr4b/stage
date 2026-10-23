package risk

import (
	"testing"
)

// Named test for I9
func TestEpssNeverChangesBodTier(t *testing.T) {
	// We create multiple findings with identical configurations except EPSS
	findings := []ScoredFinding{
		{ID: "F1", BODTier: 30, EPSSScore: 0.9},
		{ID: "F2", BODTier: 7, EPSSScore: 0.1},
		{ID: "F3", BODTier: 30, EPSSScore: 0.2},
		{ID: "F4", BODTier: 30, EPSSScore: 0.5},
		{ID: "F5", BODTier: 14, EPSSScore: 0.99},
	}
	
	// If EPSS influenced BODTier, F1 (EPSS 0.9) might jump ahead of F2 (EPSS 0.1, Tier 7).
	// But our rule is strict: BODTier comes first.
	
	RankFindings(findings)
	
	expectedOrder := []string{"F2", "F5", "F1", "F4", "F3"}
	
	for i, f := range findings {
		if f.ID != expectedOrder[i] {
			t.Errorf("At index %d, expected %s, got %s", i, expectedOrder[i], f.ID)
		}
	}
	
	// Explicitly verify the property for F1 vs F2
	f1Idx, f2Idx := -1, -1
	for i, f := range findings {
		if f.ID == "F1" { f1Idx = i }
		if f.ID == "F2" { f2Idx = i }
	}
	
	if f1Idx < f2Idx {
		t.Error("Invariant I9 violated: F1 (Tier 30, High EPSS) jumped ahead of F2 (Tier 7, Low EPSS)")
	}
}
