package resolver

import (
	"fmt"
	"testing"
)

// TestP211AmbiguousFalseMergeBias is the most critical test in Phase 2.
// It ensures that ambiguous signals (shared subnet + similar hostname, etc.)
// NEVER result in an unflagged merge (NeedsReview = false).
// They must either be "no merge" or "merge WITH review flag".
func TestP211AmbiguousFalseMergeBias(t *testing.T) {
	// A fixture set of ambiguous cases
	ambiguousFixtures := []struct {
		name  string
		metaA ProbabilisticMetadata
		metaB ProbabilisticMetadata
	}{
		{
			name: "Same subnet, similar hostname (web-01 vs web-02), different OS",
			metaA: ProbabilisticMetadata{Hostname: "web-01", Subnet: "10.0.0.0/24", OS: "Ubuntu 20.04", FirstSeen: 1000},
			metaB: ProbabilisticMetadata{Hostname: "web-02", Subnet: "10.0.0.0/24", OS: "CentOS 7", FirstSeen: 2000},
		},
		{
			name: "Same OS, same subnet, completely different hostname",
			metaA: ProbabilisticMetadata{Hostname: "database-primary", Subnet: "192.168.1.0/24", OS: "RHEL 8", FirstSeen: 1000},
			metaB: ProbabilisticMetadata{Hostname: "cache-node-1", Subnet: "192.168.1.0/24", OS: "RHEL 8", FirstSeen: 1000},
		},
		{
			name: "Same hostname, different subnet, different OS (recycled name?)",
			metaA: ProbabilisticMetadata{Hostname: "nginx-proxy", Subnet: "172.16.0.0/16", OS: "Alpine", FirstSeen: 1000},
			metaB: ProbabilisticMetadata{Hostname: "nginx-proxy", Subnet: "10.10.10.0/24", OS: "Debian", FirstSeen: 9000000},
		},
		{
			name: "Everything matches except FirstSeen is years apart",
			metaA: ProbabilisticMetadata{Hostname: "desktop-xyz", Subnet: "10.1.1.0/24", OS: "Windows 10", FirstSeen: 1000},
			metaB: ProbabilisticMetadata{Hostname: "desktop-xyz", Subnet: "10.1.1.0/24", OS: "Windows 10", FirstSeen: 1000 + 3*365*86400}, // 3 years later
		},
		{
			name: "Only FirstSeen matches",
			metaA: ProbabilisticMetadata{Hostname: "a", Subnet: "1.1.1.0/24", OS: "A", FirstSeen: 1000},
			metaB: ProbabilisticMetadata{Hostname: "b", Subnet: "2.2.2.0/24", OS: "B", FirstSeen: 1000},
		},
	}

	for i := 0; i < 100; i++ {
		// Fuzz slightly by generating 100 synthetic ambiguous cases
		nameA := fmt.Sprintf("host-%d", i)
		nameB := fmt.Sprintf("host-%d", i+1)
		
		ambiguousFixtures = append(ambiguousFixtures, struct {
			name  string
			metaA ProbabilisticMetadata
			metaB ProbabilisticMetadata
		}{
			name: fmt.Sprintf("Fuzz-case-%d", i),
			metaA: ProbabilisticMetadata{Hostname: nameA, Subnet: "10.0.0.0/24", OS: "Linux", FirstSeen: int64(i * 1000)},
			metaB: ProbabilisticMetadata{Hostname: nameB, Subnet: "10.0.0.0/24", OS: "Linux", FirstSeen: int64((i+1) * 1000)},
		})
	}

	unflaggedMerges := 0

	for _, fixture := range ambiguousFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			a := &probSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0, meta: fixture.metaA}
			b := &probSignal{sigType: "ip", value: "10.0.0.2", conf: 1.0, meta: fixture.metaB}

			decision := ProbabilisticCompare(a, b)

			// The core requirement: 0 unflagged merges across the ambiguous fixture set.
			if decision.ShouldMerge && !decision.NeedsReview {
				unflaggedMerges++
				t.Errorf("CRITICAL FALSE MERGE: Ambiguous case resulted in an UNFLAGGED merge! Score: %f\nCase: %s\nMetaA: %+v\nMetaB: %+v",
					decision.Confidence, fixture.name, fixture.metaA, fixture.metaB)
			}
			
			// Also ensure Invariant I1 (never auto-merge from heuristic tier)
			if decision.Tier == TierHeuristic && decision.ShouldMerge {
				t.Errorf("INVARIANT I1 VIOLATION: Heuristic tier auto-merged!")
			}
		})
	}

	if unflaggedMerges > 0 {
		t.Fatalf("RELEASE BLOCKER: %d unflagged merges detected in the ambiguous fixture set. Must be 0.", unflaggedMerges)
	} else {
		t.Logf("Passed: 0 unflagged merges across %d ambiguous test cases.", len(ambiguousFixtures))
	}
}
