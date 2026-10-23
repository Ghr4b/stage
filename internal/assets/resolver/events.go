package resolver

import (
	"context"
)

// EventBus interface for publishing events
type EventBus interface {
	Publish(ctx context.Context, subject string, payload interface{}) error
}

// NewAssetEvent is the payload for a newly discovered asset
type NewAssetEvent struct {
	AssetID   string
	FirstSeen string // SignalType that discovered it
	Value     string
}
