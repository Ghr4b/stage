package resolver

import (
	"time"
)

// AssetState represents the lifecycle state of an asset.
type AssetState string

const (
	StateActive   AssetState = "active"
	StateStale    AssetState = "stale"
	StateArchived AssetState = "archived"
)

// AssetClass defines the staleness windows for a given class of asset.
type AssetClass struct {
	Name            string
	StaleWindow     time.Duration
	ArchiveWindow   time.Duration // Time after becoming stale to become archived
}

var DefaultAssetClasses = map[string]AssetClass{
	"server":     {Name: "server", StaleWindow: 30 * 24 * time.Hour, ArchiveWindow: 60 * 24 * time.Hour},
	"container":  {Name: "container", StaleWindow: 1 * 24 * time.Hour, ArchiveWindow: 7 * 24 * time.Hour},
	"workstation":{Name: "workstation", StaleWindow: 14 * 24 * time.Hour, ArchiveWindow: 30 * 24 * time.Hour},
}

// EvaluateState determines the correct state of an asset based on its last seen time.
func EvaluateState(class string, lastSeen time.Time, now time.Time) AssetState {
	cfg, ok := DefaultAssetClasses[class]
	if !ok {
		// Fallback to server defaults
		cfg = DefaultAssetClasses["server"]
	}

	age := now.Sub(lastSeen)

	if age >= cfg.StaleWindow+cfg.ArchiveWindow {
		return StateArchived
	}
	if age >= cfg.StaleWindow {
		return StateStale
	}
	return StateActive
}

// In this project, a hard-delete code path for staleness does NOT exist.
// Archived records are retained indefinitely for historical querying.
