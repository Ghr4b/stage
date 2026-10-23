package resolver

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// inMemoryMergeStore implements MergeStore for testing.
type inMemoryMergeStore struct {
	mu           sync.Mutex
	assets       map[string]AssetSnapshot
	lineages     map[string]MergeLineage
	nextMergeID  int
	nextAssetID  int
}

func newInMemoryMergeStore() *inMemoryMergeStore {
	return &inMemoryMergeStore{
		assets:   make(map[string]AssetSnapshot),
		lineages: make(map[string]MergeLineage),
	}
}

func (m *inMemoryMergeStore) addFixture(asset AssetSnapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets[asset.AssetID] = asset
}

func (m *inMemoryMergeStore) SnapshotAsset(ctx context.Context, assetID string) (AssetSnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if asset, ok := m.assets[assetID]; ok {
		// Deep copy slices to ensure snapshot doesn't mutate
		snap := asset
		snap.Findings = append([]string(nil), asset.Findings...)
		snap.ScanHistory = append([]string(nil), asset.ScanHistory...)
		return snap, nil
	}
	return AssetSnapshot{}, fmt.Errorf("asset %s not found", assetID)
}

func (m *inMemoryMergeStore) CreateMergeRecord(ctx context.Context, lineage MergeLineage) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Generate IDs
	m.nextMergeID++
	m.nextAssetID++
	mergeID := fmt.Sprintf("merge-%d", m.nextMergeID)
	mergedAssetID := fmt.Sprintf("asset-%d", m.nextAssetID)

	lineage.MergeID = mergeID
	lineage.MergedAssetID = mergedAssetID

	// 2. Perform the merge: delete old, create new
	delete(m.assets, lineage.SourceAssetA.AssetID)
	delete(m.assets, lineage.SourceAssetB.AssetID)

	mergedAsset := AssetSnapshot{
		AssetID:         mergedAssetID,
		Findings:        append(append([]string(nil), lineage.SourceAssetA.Findings...), lineage.SourceAssetB.Findings...),
		ScanHistory:     append(append([]string(nil), lineage.SourceAssetA.ScanHistory...), lineage.SourceAssetB.ScanHistory...),
		CriticalityTier: lineage.SourceAssetA.CriticalityTier, // Simple resolution for test
	}
	m.assets[mergedAssetID] = mergedAsset

	// 3. Save lineage
	m.lineages[mergeID] = lineage

	return mergedAssetID, mergeID, nil
}

func (m *inMemoryMergeStore) GetMergeRecord(ctx context.Context, mergeID string) (MergeLineage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if l, ok := m.lineages[mergeID]; ok {
		return l, nil
	}
	return MergeLineage{}, errors.New("merge record not found")
}

func (m *inMemoryMergeStore) ExecuteUnmerge(ctx context.Context, mergeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	lineage, ok := m.lineages[mergeID]
	if !ok {
		return errors.New("merge record not found")
	}

	// 1. Delete merged asset
	delete(m.assets, lineage.MergedAssetID)

	// 2. Restore source assets from snapshots (deep copy)
	snapA := lineage.SourceAssetA
	snapA.Findings = append([]string(nil), snapA.Findings...)
	snapA.ScanHistory = append([]string(nil), snapA.ScanHistory...)
	m.assets[snapA.AssetID] = snapA

	snapB := lineage.SourceAssetB
	snapB.Findings = append([]string(nil), snapB.Findings...)
	snapB.ScanHistory = append([]string(nil), snapB.ScanHistory...)
	m.assets[snapB.AssetID] = snapB

	// 3. Update lineage
	lineage.Unmerged = true
	lineage.UnmergeTime = time.Now().UTC()
	m.lineages[mergeID] = lineage

	return nil
}

// TestReversibleMergeWithLineage tests P2-6 requirements.
func TestReversibleMergeWithLineage(t *testing.T) {
	ctx := context.Background()
	store := newInMemoryMergeStore()
	svc := &MergeService{Store: store}

	// Setup fixtures
	fixtureA := AssetSnapshot{
		AssetID:         "a-1",
		Findings:        []string{"f-1", "f-2"},
		ScanHistory:     []string{"scan-100"},
		CriticalityTier: "tier-1",
	}
	fixtureB := AssetSnapshot{
		AssetID:         "a-2",
		Findings:        []string{"f-3"},
		ScanHistory:     []string{"scan-101"},
		CriticalityTier: "tier-2",
	}

	store.addFixture(fixtureA)
	store.addFixture(fixtureB)

	// 1. Merge
	mergeID, err := svc.Merge(ctx, "a-1", "a-2", TierProbabilistic, 0.85)
	if err != nil {
		t.Fatalf("Merge failed: %v", err)
	}

	// Verify pre-merge assets are gone
	if _, err := store.SnapshotAsset(ctx, "a-1"); err == nil {
		t.Error("Asset a-1 should not exist after merge")
	}
	
	// 2. Retrieve lineage
	lineage, err := store.GetMergeRecord(ctx, mergeID)
	if err != nil {
		t.Fatalf("GetMergeRecord failed: %v", err)
	}
	if lineage.Tier != TierProbabilistic || lineage.Confidence != 0.85 {
		t.Errorf("Lineage metadata mismatch: tier=%s, conf=%f", lineage.Tier, lineage.Confidence)
	}

	// 3. Unmerge
	if err := svc.Unmerge(ctx, mergeID); err != nil {
		t.Fatalf("Unmerge failed: %v", err)
	}

	// 4. Verify Post-unmerge equality
	// "Post-unmerge record equality check against pre-merge snapshot
	// (byte-for-byte on the fields that matter: findings, scan history, criticality tier)"
	
	restoredA, err := store.SnapshotAsset(ctx, "a-1")
	if err != nil {
		t.Fatalf("Failed to retrieve a-1 post-unmerge: %v", err)
	}
	restoredB, err := store.SnapshotAsset(ctx, "a-2")
	if err != nil {
		t.Fatalf("Failed to retrieve a-2 post-unmerge: %v", err)
	}

	if !reflect.DeepEqual(restoredA, fixtureA) {
		t.Errorf("Restored A != Fixture A.\nGot: %+v\nWant: %+v", restoredA, fixtureA)
	}
	
	if !reflect.DeepEqual(restoredB, fixtureB) {
		t.Errorf("Restored B != Fixture B.\nGot: %+v\nWant: %+v", restoredB, fixtureB)
	}

	// 5. Verify lineage retained
	finalLineage, err := store.GetMergeRecord(ctx, mergeID)
	if err != nil {
		t.Fatalf("Lineage should be retained after unmerge: %v", err)
	}
	if !finalLineage.Unmerged {
		t.Error("Lineage record not marked as unmerged")
	}
	if finalLineage.UnmergeTime.IsZero() {
		t.Error("Unmerge time not recorded")
	}
}

func TestUnmergeRoundTripsScenarios(t *testing.T) {
	ctx := context.Background()
	store := newInMemoryMergeStore()
	svc := &MergeService{Store: store}

	// Scenario 1: Deterministic tier merge
	store.addFixture(AssetSnapshot{AssetID: "s1-a", Findings: []string{"f1"}, CriticalityTier: "tier-1"})
	store.addFixture(AssetSnapshot{AssetID: "s1-b", Findings: []string{"f2"}, CriticalityTier: "tier-1"})
	
	// Scenario 2: Probabilistic tier merge
	store.addFixture(AssetSnapshot{AssetID: "s2-a", Findings: []string{"f3"}, CriticalityTier: "tier-2"})
	store.addFixture(AssetSnapshot{AssetID: "s2-b", Findings: []string{"f4"}, CriticalityTier: "tier-2"})
	
	// Scenario 3: Heavy history merge
	store.addFixture(AssetSnapshot{AssetID: "s3-a", Findings: []string{"f5", "f6", "f7"}, ScanHistory: []string{"sh-1", "sh-2"}, CriticalityTier: "tier-1"})
	store.addFixture(AssetSnapshot{AssetID: "s3-b", Findings: []string{"f8"}, ScanHistory: []string{"sh-3"}, CriticalityTier: "tier-3"})

	scenarios := []struct{
		a, b string
		tier Tier
		conf float64
	}{
		{"s1-a", "s1-b", TierDeterministic, 1.0},
		{"s2-a", "s2-b", TierProbabilistic, 0.75},
		{"s3-a", "s3-b", TierProbabilistic, 0.90},
	}

	for i, sc := range scenarios {
		t.Run(fmt.Sprintf("Scenario_%d", i+1), func(t *testing.T) {
			origA, _ := store.SnapshotAsset(ctx, sc.a)
			origB, _ := store.SnapshotAsset(ctx, sc.b)

			mID, err := svc.Merge(ctx, sc.a, sc.b, sc.tier, sc.conf)
			if err != nil { t.Fatalf("Merge failed: %v", err) }
			
			err = svc.Unmerge(ctx, mID)
			if err != nil { t.Fatalf("Unmerge failed: %v", err) }
			
			restA, _ := store.SnapshotAsset(ctx, sc.a)
			restB, _ := store.SnapshotAsset(ctx, sc.b)
			
			if !reflect.DeepEqual(origA, restA) { t.Errorf("A mismatch in scenario %d", i+1) }
			if !reflect.DeepEqual(origB, restB) { t.Errorf("B mismatch in scenario %d", i+1) }
		})
	}
}
