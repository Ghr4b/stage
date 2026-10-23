package risk

import (
	"encoding/json"
	"testing"
)

// P5-6: Continuous re-evaluation
func TestContinuousReEvaluation(t *testing.T) {
	bTrue := true
	bFalse := false
	
	// Base state: KEV, Publicly Exposed, Automatable, Full Tech Impact -> Tier 3
	initialScore, _ := RecomputeScore(&bTrue, true, &bTrue, true, "standard", 0.5, "act")
	if initialScore.BODTier != 3 {
		t.Fatalf("Expected initial BODTier 3, got %d", initialScore.BODTier)
	}

	// Event: exposure flips to private
	recomputedScore1, _ := RecomputeScore(&bFalse, true, &bTrue, true, "standard", 0.5, "act")
	if recomputedScore1.BODTier <= initialScore.BODTier {
		t.Errorf("Expected deadline to lengthen (from %d) when exposure flips to private, got %d", initialScore.BODTier, recomputedScore1.BODTier)
	}
	
	// Event: new KEV entry (KEV flips to true for a previously false finding)
	initialScore2, _ := RecomputeScore(&bTrue, false, &bTrue, true, "standard", 0.5, "track")
	if initialScore2.BODTier != 30 {
		t.Fatalf("Expected initial BODTier 30 for non-KEV, got %d", initialScore2.BODTier)
	}
	
	recomputedScore2, _ := RecomputeScore(&bTrue, true, &bTrue, true, "standard", 0.5, "track")
	if recomputedScore2.BODTier >= initialScore2.BODTier {
		t.Errorf("Expected deadline to shorten (from %d) when KEV becomes true, got %d", initialScore2.BODTier, recomputedScore2.BODTier)
	}
}

// P5-7: Explainability output schema validation
func TestExplainabilityOutputSchema(t *testing.T) {
	bTrue := true
	
	// Without override
	out1, err := RecomputeScore(&bTrue, true, &bTrue, true, "standard", 0.9, "act")
	if err != nil {
		t.Fatal(err)
	}
	if out1.CriticalityOverride != nil {
		t.Errorf("Expected CriticalityOverride to be null, got %v", *out1.CriticalityOverride)
	}
	
	// With override
	out2, err := RecomputeScore(&bTrue, true, &bTrue, true, "mission_critical", 0.9, "act")
	if err != nil {
		t.Fatal(err)
	}
	if out2.CriticalityOverride == nil {
		t.Error("Expected CriticalityOverride to be populated")
	}
	if out2.BODTier != 1 {
		t.Errorf("Expected tightened tier 1, got %d", out2.BODTier)
	}
	
	// Check JSON marshaling
	jsonBytes, err := json.Marshal(out2)
	if err != nil {
		t.Fatal(err)
	}
	var unmarshaled map[string]interface{}
	json.Unmarshal(jsonBytes, &unmarshaled)
	
	expectedFields := []string{"bod_tier", "criticality_override", "epss_rank", "ssvc_bucket"}
	for _, f := range expectedFields {
		if _, ok := unmarshaled[f]; !ok {
			t.Errorf("Missing expected field %s in JSON output", f)
		}
	}
}
