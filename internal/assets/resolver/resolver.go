package resolver

import (
	"context"
	"tijeri/internal/assets"
)

// Tier represents the resolution tier that produced a merge decision.
type Tier string

const (
	TierDeterministic Tier = "deterministic"
	TierProbabilistic Tier = "probabilistic"
	TierHeuristic     Tier = "heuristic"
	TierNone          Tier = "none"
)

// MergeDecision is the outcome of comparing two signals.
type MergeDecision struct {
	ShouldMerge bool
	Tier        Tier
	Confidence  float64
	NeedsReview bool // Must be true for probabilistic and heuristic tiers
}

// CompareFunc is the function signature for comparing two signals.
// This is the function that blocking prevents from being called across blocks.
type CompareFunc func(a, b assets.IdentitySignal) MergeDecision

// BlockKey is a string that represents which block a signal belongs to.
type BlockKey string

// Blocker assigns a signal to a block. Only signals in the same block
// are compared, which keeps comparison count at O(N²/K) instead of O(N²).
type Blocker interface {
	Block(signal assets.IdentitySignal) BlockKey
}

// Resolver implements AssetIdentityResolver with tiered correlation.
type Resolver struct {
	Blocker     Blocker
	CompareFunc CompareFunc
	Store       ResolverStore
	EventBus    EventBus
}

// ResolverStore is the persistence layer for the resolver.
type ResolverStore interface {
	// LookupByBlock returns all existing asset IDs in the given block.
	LookupByBlock(ctx context.Context, block BlockKey) ([]StoredSignal, error)
	// StoreSignal persists a signal and its resolved asset ID.
	StoreSignal(ctx context.Context, assetID string, signal assets.IdentitySignal, block BlockKey) error
	// NextAssetID generates a new unique asset ID.
	NextAssetID(ctx context.Context) (string, error)
}

// StoredSignal is a signal that has already been resolved and stored.
type StoredSignal struct {
	AssetID string
	Signal  assets.IdentitySignal
}

// Resolve takes an incoming signal, determines its block, compares it against
// existing signals in that block only, and returns the resolved asset ID.
func (r *Resolver) Resolve(ctx context.Context, signal assets.IdentitySignal) (string, error) {
	block := r.Blocker.Block(signal)

	existing, err := r.Store.LookupByBlock(ctx, block)
	if err != nil {
		return "", err
	}

	// Compare incoming signal against all existing signals in this block only.
	var bestMatch *StoredSignal
	var bestDecision MergeDecision

	for i := range existing {
		decision := r.CompareFunc(signal, existing[i].Signal)
		if decision.ShouldMerge && decision.Confidence > bestDecision.Confidence {
			bestMatch = &existing[i]
			bestDecision = decision
		}
	}

	if bestMatch != nil {
		// Merge into the existing asset
		if err := r.Store.StoreSignal(ctx, bestMatch.AssetID, signal, block); err != nil {
			return "", err
		}
		return bestMatch.AssetID, nil
	}

	// No match — create a new asset
	newID, err := r.Store.NextAssetID(ctx)
	if err != nil {
		return "", err
	}
	if err := r.Store.StoreSignal(ctx, newID, signal, block); err != nil {
		return "", err
	}
	
	// P2-10: Emit a distinct "new asset" event on first-ever sighting
	if r.EventBus != nil {
		event := NewAssetEvent{
			AssetID:   newID,
			FirstSeen: signal.SignalType(),
			Value:     signal.Value(),
		}
		_ = r.EventBus.Publish(ctx, "assets.new", event)
	}
	
	return newID, nil
}

// Ensure Resolver implements AssetIdentityResolver
var _ assets.AssetIdentityResolver = (*Resolver)(nil)
