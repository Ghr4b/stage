package resolver

import (
	"context"
	"testing"
	"time"
)

// mockQueryStore simulates a store that supports "include archived" queries.
type mockQueryStore struct {
	assets map[string]assetRecord
}

type assetRecord struct {
	id       string
	class    string
	lastSeen time.Time
}

func (s *mockQueryStore) Query(ctx context.Context, includeArchived bool, now time.Time) []string {
	var results []string
	for _, a := range s.assets {
		state := EvaluateState(a.class, a.lastSeen, now)
		if state == StateArchived && !includeArchived {
			continue
		}
		results = append(results, a.id)
	}
	return results
}

func TestStalenessTransitions(t *testing.T) {
	now := time.Now()

	testCases := []struct {
		name      string
		class     string
		age       time.Duration
		wantState AssetState
	}{
		// Server: Stale at 30d, Archive at 90d total (30+60)
		{"server active (0d)", "server", 0, StateActive},
		{"server active (29d)", "server", 29 * 24 * time.Hour, StateActive},
		{"server stale (31d)", "server", 31 * 24 * time.Hour, StateStale},
		{"server stale (89d)", "server", 89 * 24 * time.Hour, StateStale},
		{"server archived (91d)", "server", 91 * 24 * time.Hour, StateArchived},
		{"server archived (6 months)", "server", 180 * 24 * time.Hour, StateArchived},

		// Container: Stale at 1d, Archive at 8d total (1+7)
		{"container active (12h)", "container", 12 * time.Hour, StateActive},
		{"container stale (2d)", "container", 2 * 24 * time.Hour, StateStale},
		{"container archived (10d)", "container", 10 * 24 * time.Hour, StateArchived},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			lastSeen := now.Add(-tc.age)
			state := EvaluateState(tc.class, lastSeen, now)
			if state != tc.wantState {
				t.Errorf("EvaluateState() = %v, want %v", state, tc.wantState)
			}
		})
	}
}

func TestArchivedQuerying(t *testing.T) {
	now := time.Now()
	store := &mockQueryStore{
		assets: map[string]assetRecord{
			"active1": {"active1", "server", now.Add(-10 * 24 * time.Hour)}, // 10 days old -> active
			"stale1":  {"stale1", "server", now.Add(-40 * 24 * time.Hour)},  // 40 days old -> stale
			"archived1": {"archived1", "server", now.Add(-180 * 24 * time.Hour)}, // 6 months old -> archived
		},
	}

	ctx := context.Background()

	// 1. Without includeArchived, we should get active1 and stale1
	normalResults := store.Query(ctx, false, now)
	if len(normalResults) != 2 {
		t.Errorf("Expected 2 results without includeArchived, got %d", len(normalResults))
	}
	for _, id := range normalResults {
		if id == "archived1" {
			t.Error("Archived record returned when includeArchived=false")
		}
	}

	// 2. With includeArchived, we should get all 3, proving archived records are retained and queryable
	// 6+ months later.
	archivedResults := store.Query(ctx, true, now)
	if len(archivedResults) != 3 {
		t.Errorf("Expected 3 results with includeArchived, got %d", len(archivedResults))
	}
	
	foundArchived := false
	for _, id := range archivedResults {
		if id == "archived1" {
			foundArchived = true
		}
	}
	if !foundArchived {
		t.Error("Archived record NOT returned when includeArchived=true")
	}
}
