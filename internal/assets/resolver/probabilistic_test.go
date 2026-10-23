package resolver

import (
	"testing"
	"tijeri/internal/assets"
)

type probSignal struct {
	sigType string
	value   string
	conf    float64
	meta    ProbabilisticMetadata
}

func (s *probSignal) SignalType() string                { return s.sigType }
func (s *probSignal) Value() string                     { return s.value }
func (s *probSignal) Confidence() float64               { return s.conf }
func (s *probSignal) Metadata() ProbabilisticMetadata   { return s.meta }

var _ assets.IdentitySignal = (*probSignal)(nil)
var _ ProbabilisticSignal = (*probSignal)(nil)

func TestProbabilisticAboveThresholdMergesWithReview(t *testing.T) {
	// High similarity signals: same hostname, same subnet, same OS, same first-seen
	a := &probSignal{
		sigType: "ip", value: "10.0.0.1", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "web-server-01", Subnet: "10.0.0.0/24", OS: "Ubuntu 22.04", FirstSeen: 1000000,
		},
	}
	b := &probSignal{
		sigType: "ip", value: "10.0.0.2", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "web-server-01", Subnet: "10.0.0.0/24", OS: "Ubuntu 22.04", FirstSeen: 1000000,
		},
	}

	decision := ProbabilisticCompare(a, b)
	if !decision.ShouldMerge {
		t.Errorf("Expected merge for high-similarity signals, got no merge (score would be ~1.0)")
	}
	if !decision.NeedsReview {
		t.Error("CRITICAL: Probabilistic tier merge MUST have NeedsReview=true")
	}
	if decision.Tier != TierProbabilistic {
		t.Errorf("Expected tier probabilistic, got %s", decision.Tier)
	}
}

func TestProbabilisticBelowThresholdNoMerge(t *testing.T) {
	// Very dissimilar signals
	a := &probSignal{
		sigType: "ip", value: "10.0.0.1", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "web-server-01", Subnet: "10.0.0.0/24", OS: "Ubuntu 22.04", FirstSeen: 1000000,
		},
	}
	b := &probSignal{
		sigType: "ip", value: "192.168.1.1", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "db-master-prod", Subnet: "192.168.1.0/24", OS: "CentOS 7", FirstSeen: 5000000,
		},
	}

	decision := ProbabilisticCompare(a, b)
	if decision.ShouldMerge {
		t.Error("Should NOT merge dissimilar signals")
	}
}

func TestHeuristicTierNeverAutoMerges(t *testing.T) {
	// Mid-range similarity: same subnet and OS but different hostname and first-seen
	a := &probSignal{
		sigType: "ip", value: "10.0.0.1", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "web-server-01", Subnet: "10.0.0.0/24", OS: "Ubuntu 22.04", FirstSeen: 1000000,
		},
	}
	b := &probSignal{
		sigType: "ip", value: "10.0.0.2", conf: 1.0,
		meta: ProbabilisticMetadata{
			Hostname: "database-master", Subnet: "10.0.0.0/24", OS: "Ubuntu 22.04", FirstSeen: 3000000,
		},
	}

	decision := ProbabilisticCompare(a, b)

	// This case should land in the heuristic range (subnet + OS match but hostname mismatch)
	// Score: 0.0 (hostname) + 0.25 (subnet) + 0.20 (OS) + ~0 (first-seen) ≈ 0.45
	if decision.ShouldMerge {
		t.Error("INVARIANT I1 VIOLATION: Heuristic-tier case auto-merged! Must never auto-merge.")
	}
	if decision.Tier == TierHeuristic && !decision.NeedsReview {
		t.Error("Heuristic tier should have NeedsReview=true")
	}
}

func TestProbabilisticScoreThresholdTable(t *testing.T) {
	tests := []struct {
		name       string
		metaA      ProbabilisticMetadata
		metaB      ProbabilisticMetadata
		wantMerge  bool
		wantTier   Tier
		wantReview bool
	}{
		{
			name: "identical metadata → merge with review",
			metaA: ProbabilisticMetadata{Hostname: "srv-01", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 100},
			metaB: ProbabilisticMetadata{Hostname: "srv-01", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 100},
			wantMerge: true, wantTier: TierProbabilistic, wantReview: true,
		},
		{
			name: "hostname + subnet match, different OS and time → merge with review",
			metaA: ProbabilisticMetadata{Hostname: "srv-01", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 100},
			metaB: ProbabilisticMetadata{Hostname: "srv-01", Subnet: "10.0.0.0/24", OS: "CentOS", FirstSeen: 200},
			wantMerge: true, wantTier: TierProbabilistic, wantReview: true,
		},
		{
			name: "only subnet + OS → heuristic queue (no auto-merge)",
			metaA: ProbabilisticMetadata{Hostname: "alpha", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 100},
			metaB: ProbabilisticMetadata{Hostname: "zeta", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 3000000},
			wantMerge: false, wantTier: TierHeuristic, wantReview: true,
		},
		{
			name: "nothing matches → no merge",
			metaA: ProbabilisticMetadata{Hostname: "a", Subnet: "10.0.0.0/24", OS: "Ubuntu", FirstSeen: 100},
			metaB: ProbabilisticMetadata{Hostname: "z", Subnet: "192.168.0.0/24", OS: "Windows", FirstSeen: 9000000},
			wantMerge: false, wantTier: TierNone, wantReview: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := &probSignal{sigType: "ip", value: "a", conf: 1.0, meta: tc.metaA}
			b := &probSignal{sigType: "ip", value: "b", conf: 1.0, meta: tc.metaB}

			d := ProbabilisticCompare(a, b)

			if d.ShouldMerge != tc.wantMerge {
				t.Errorf("ShouldMerge = %v, want %v (confidence=%f)", d.ShouldMerge, tc.wantMerge, d.Confidence)
			}
			if d.Tier != tc.wantTier {
				t.Errorf("Tier = %s, want %s (confidence=%f)", d.Tier, tc.wantTier, d.Confidence)
			}
			if d.ShouldMerge && !d.NeedsReview {
				t.Error("CRITICAL: Any probabilistic/heuristic merge must have NeedsReview=true")
			}
		})
	}
}
