package assets

import (
	"context"
)

type IdentitySignal interface {
	SignalType() string // "mac_address", "agent_uuid", "cloud_arn", "image_digest", "fqdn"
	Value() string
	Confidence() float64
}

type AssetIdentityResolver interface {
	Resolve(ctx context.Context, signal IdentitySignal) (assetID string, err error)
}
// Asset and ScannerAdapter definitions moved to models and adapters.
