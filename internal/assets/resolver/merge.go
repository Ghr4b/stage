package resolver

import (
	"context"
	"errors"
	"time"
)

// AssetSnapshot represents the state of an asset before a merge,
// containing the fields that matter for restoration upon unmerge.
type AssetSnapshot struct {
	AssetID         string
	Findings        []string // Just IDs for simulation
	ScanHistory     []string // Just scan run IDs
	CriticalityTier string
}

// MergeLineage records the history of a merge operation.
type MergeLineage struct {
	MergeID         string
	SourceAssetA    AssetSnapshot
	SourceAssetB    AssetSnapshot
	MergedAssetID   string
	Tier            Tier
	Confidence      float64
	Timestamp       time.Time
	Unmerged        bool
	UnmergeTime     time.Time
}

// MergeStore defines the persistence interface for merges and lineage.
type MergeStore interface {
	// SnapshotAsset returns the current state of an asset to store in lineage.
	SnapshotAsset(ctx context.Context, assetID string) (AssetSnapshot, error)
	
	// CreateMergeRecord saves the lineage record and performs the merge in the DB.
	// Returns the ID of the new merged asset, and a generated MergeID.
	CreateMergeRecord(ctx context.Context, lineage MergeLineage) (string, string, error)
	
	// GetMergeRecord retrieves a lineage record.
	GetMergeRecord(ctx context.Context, mergeID string) (MergeLineage, error)
	
	// ExecuteUnmerge restores the source assets from their snapshots and marks the lineage unmerged.
	ExecuteUnmerge(ctx context.Context, mergeID string) error
}

// MergeService handles reversible merges with lineage.
type MergeService struct {
	Store MergeStore
}

// Merge merges asset A and B into a single new asset.
func (s *MergeService) Merge(ctx context.Context, assetA, assetB string, tier Tier, conf float64) (string, error) {
	snapA, err := s.Store.SnapshotAsset(ctx, assetA)
	if err != nil {
		return "", err
	}
	
	snapB, err := s.Store.SnapshotAsset(ctx, assetB)
	if err != nil {
		return "", err
	}

	lineage := MergeLineage{
		SourceAssetA: snapA,
		SourceAssetB: snapB,
		Tier:         tier,
		Confidence:   conf,
		Timestamp:    time.Now().UTC(),
	}

	_, mergeID, err := s.Store.CreateMergeRecord(ctx, lineage)
	if err != nil {
		return "", err
	}

	return mergeID, nil
}

// Unmerge reverses a previous merge operation.
func (s *MergeService) Unmerge(ctx context.Context, mergeID string) error {
	record, err := s.Store.GetMergeRecord(ctx, mergeID)
	if err != nil {
		return err
	}
	
	if record.Unmerged {
		return errors.New("already unmerged")
	}

	return s.Store.ExecuteUnmerge(ctx, mergeID)
}
