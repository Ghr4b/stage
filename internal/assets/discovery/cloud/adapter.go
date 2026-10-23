package cloud

import (
	"context"
)

type CloudDiscoveryAdapter interface {
	// Sync Full periodic reconciliation (e.g. running CloudQuery)
	Sync(ctx context.Context) error
	
	// Query ad-hoc queries (e.g. running Steampipe)
	Query(ctx context.Context, query string) ([]map[string]interface{}, error)
	
	// ProcessEvent Event-driven update (e.g. processing CloudTrail event)
	ProcessEvent(ctx context.Context, eventPayload []byte) error
}
