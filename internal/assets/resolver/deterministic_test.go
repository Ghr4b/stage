package resolver

import (
	"testing"
)

func TestDeterministicExactMatch(t *testing.T) {
	testCases := []struct {
		name      string
		sigType   string
		valueA    string
		valueB    string
		wantMerge bool
	}{
		{"cloud_instance_id exact match", "cloud_instance_id", "i-0123456789abcdef0", "i-0123456789abcdef0", true},
		{"hardware_serial exact match", "hardware_serial", "SN-ABC-123", "SN-ABC-123", true},
		{"tpm_uuid exact match", "tpm_uuid", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440000", true},
		{"cloud_instance_id near-miss (off-by-one)", "cloud_instance_id", "i-0123456789abcdef0", "i-0123456789abcdef1", false},
		{"hardware_serial near-miss", "hardware_serial", "SN-ABC-123", "SN-ABC-124", false},
		{"tpm_uuid near-miss", "tpm_uuid", "550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-446655440001", false},
		{"non-deterministic type ignored", "ip", "10.0.0.1", "10.0.0.1", false},
		{"mac_address not in deterministic tier", "mac_address", "00:11:22:33:44:55", "00:11:22:33:44:55", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			a := &testSignal{sigType: tc.sigType, value: tc.valueA, conf: 1.0}
			b := &testSignal{sigType: tc.sigType, value: tc.valueB, conf: 1.0}

			decision := DeterministicCompare(a, b)

			if decision.ShouldMerge != tc.wantMerge {
				t.Errorf("ShouldMerge = %v, want %v", decision.ShouldMerge, tc.wantMerge)
			}

			if decision.ShouldMerge {
				// Deterministic tier merges must NOT have review flag
				if decision.NeedsReview {
					t.Error("CRITICAL: Deterministic tier merge has NeedsReview=true, must be false")
				}
				if decision.Tier != TierDeterministic {
					t.Errorf("Expected tier deterministic, got %s", decision.Tier)
				}
				if decision.Confidence != 1.0 {
					t.Errorf("Expected confidence 1.0, got %f", decision.Confidence)
				}
			}
		})
	}
}

func TestDeterministicDifferentTypes(t *testing.T) {
	a := &testSignal{sigType: "cloud_instance_id", value: "i-0123456789abcdef0", conf: 1.0}
	b := &testSignal{sigType: "hardware_serial", value: "i-0123456789abcdef0", conf: 1.0}

	decision := DeterministicCompare(a, b)
	if decision.ShouldMerge {
		t.Error("Should not merge signals of different types even if values match")
	}
}
