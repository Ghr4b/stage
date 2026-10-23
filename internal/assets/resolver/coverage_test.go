package resolver

import (
	"context"
	"errors"
	"testing"
	"time"
	"tijeri/internal/assets"
)

// mockErrorStore returns errors for testing error paths
type mockErrorStore struct{}

func (m *mockErrorStore) LookupByBlock(ctx context.Context, block BlockKey) ([]StoredSignal, error) {
	if block == "lookup-error" {
		return nil, errors.New("lookup failed")
	}
	return nil, nil
}

func (m *mockErrorStore) StoreSignal(ctx context.Context, assetID string, signal assets.IdentitySignal, block BlockKey) error {
	if block == "store-error" {
		return errors.New("store failed")
	}
	return nil
}

func (m *mockErrorStore) NextAssetID(ctx context.Context) (string, error) {
	return "", errors.New("nextid failed")
}

func TestResolverErrorPaths(t *testing.T) {
	resolver := &Resolver{
		Blocker: &SubnetBlocker{},
		Store:   &mockErrorStore{},
	}
	
	ctx := context.Background()

	// 1. Lookup error
	_, err := resolver.Resolve(ctx, &testSignal{sigType: "lookup-error"})
	if err == nil {
		t.Error("Expected lookup error")
	}

	// 2. NextAssetID error
	_, err = resolver.Resolve(ctx, &testSignal{sigType: "other"})
	if err == nil {
		t.Error("Expected nextid error")
	}
}

func TestGetPackages(t *testing.T) {
	state := NewInventoryState()
	state.MergeReport(InventoryReport{
		Packages: []SoftwarePackage{{Name: "test", Version: "1.0"}},
	})
	
	pkgs := state.GetPackages()
	if len(pkgs) != 1 || pkgs[0].Name != "test" || pkgs[0].Version != "1.0" {
		t.Error("GetPackages returned unexpected result")
	}
}

func TestStalenessFallback(t *testing.T) {
	// Unknown class should fallback to server defaults
	state := EvaluateState("unknown-class", time.Now().Add(-40*24*time.Hour), time.Now())
	if state != StateStale {
		t.Errorf("Expected stale for fallback class, got %v", state)
	}
}

// errorMergeStore simulates errors in MergeStore operations
type errorMergeStore struct{}

func (s *errorMergeStore) SnapshotAsset(ctx context.Context, assetID string) (AssetSnapshot, error) {
	if assetID == "snap-error" {
		return AssetSnapshot{}, errors.New("snapshot error")
	}
	return AssetSnapshot{AssetID: assetID}, nil
}

func (s *errorMergeStore) CreateMergeRecord(ctx context.Context, lineage MergeLineage) (string, string, error) {
	if lineage.SourceAssetA.AssetID == "create-error" {
		return "", "", errors.New("create merge error")
	}
	return "", "", nil
}

func (s *errorMergeStore) GetMergeRecord(ctx context.Context, mergeID string) (MergeLineage, error) {
	if mergeID == "get-error" {
		return MergeLineage{}, errors.New("get merge error")
	}
	return MergeLineage{}, nil
}

func (s *errorMergeStore) ExecuteUnmerge(ctx context.Context, mergeID string) error {
	return errors.New("execute unmerge error")
}

func TestMergeServiceErrorPaths(t *testing.T) {
	svc := &MergeService{Store: &errorMergeStore{}}
	ctx := context.Background()

	// Merge - snapshot error
	_, err := svc.Merge(ctx, "snap-error", "other", TierNone, 0)
	if err == nil {
		t.Error("Expected error on first snapshot")
	}
	_, err = svc.Merge(ctx, "other", "snap-error", TierNone, 0)
	if err == nil {
		t.Error("Expected error on second snapshot")
	}

	// Merge - create error
	_, err = svc.Merge(ctx, "create-error", "other", TierNone, 0)
	if err == nil {
		t.Error("Expected error on create merge record")
	}

	// Unmerge - get error
	err = svc.Unmerge(ctx, "get-error")
	if err == nil {
		t.Error("Expected error on get merge record")
	}
}

func TestResolverStoreSignalError(t *testing.T) {
	resolver := &Resolver{
		Blocker: &SubnetBlocker{},
		Store:   &mockErrorStore{},
	}
	
	// Create scenario where StoreSignal fails after nextID succeeds
	// Or when StoreSignal fails on update of existing
	_, err := resolver.Resolve(context.Background(), &testSignal{sigType: "store-error"})
	if err == nil {
		t.Error("Expected store error")
	}
}
