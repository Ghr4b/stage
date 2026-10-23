package risk

import (
	"testing"
)

func TestParseVulnrichment(t *testing.T) {
	fixtureJSON := []byte(`{
		"metrics": [
			{
				"other": {
					"type": "ssvc",
					"content": {
						"id": "CVE-2023-1234",
						"options": [
							{
								"Automatable": "yes",
								"Technical Impact": "total"
							}
						]
					}
				}
			}
		]
	}`)
	
	res, err := ParseVulnrichment(fixtureJSON)
	if err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}
	if res == nil {
		t.Fatal("Expected parsed result, got nil")
	}
	
	if !res.Automatable {
		t.Error("Expected Automatable to be true")
	}
	if !res.TechnicalImpact {
		t.Error("Expected TechnicalImpact to be true (total)")
	}
}

func TestParseVulnrichment_Partial(t *testing.T) {
	fixtureJSON := []byte(`{
		"metrics": [
			{
				"other": {
					"type": "ssvc",
					"content": {
						"options": [
							{
								"Automatable": "no",
								"Technical Impact": "partial"
							}
						]
					}
				}
			}
		]
	}`)
	
	res, err := ParseVulnrichment(fixtureJSON)
	if err != nil {
		t.Fatalf("Failed to parse fixture: %v", err)
	}
	if res.Automatable {
		t.Error("Expected Automatable to be false")
	}
	if res.TechnicalImpact {
		t.Error("Expected TechnicalImpact to be false (partial)")
	}
}
