package resolver

import (
	"context"
	"testing"
	"tijeri/internal/assets"
)

type mockEventBus struct {
	Published []interface{}
}

func (m *mockEventBus) Publish(ctx context.Context, subject string, payload interface{}) error {
	m.Published = append(m.Published, payload)
	return nil
}

func TestNewAssetEventEmittedExactlyOnce(t *testing.T) {
	bus := &mockEventBus{}
	store := newInMemoryStore()
	
	// Create a dummy CompareFunc that always merges signals of the same type.
	compareFunc := func(a, b testSignal) MergeDecision {
		if a.sigType == b.sigType {
			return MergeDecision{ShouldMerge: true, Confidence: 1.0}
		}
		return MergeDecision{ShouldMerge: false}
	}
	
	resolver := &Resolver{
		Blocker:     &SubnetBlocker{},
		CompareFunc: func(a, b assets.IdentitySignal) MergeDecision {
			return compareFunc(*a.(*testSignal), *b.(*testSignal))
		},
		Store:       store,
		EventBus:    bus,
	}

	ctx := context.Background()

	// 1. First signal for a new identity -> Should emit event
	sig1 := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}
	_, err := resolver.Resolve(ctx, sig1)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(bus.Published) != 1 {
		t.Fatalf("Expected exactly 1 event published, got %d", len(bus.Published))
	}
	
	event, ok := bus.Published[0].(NewAssetEvent)
	if !ok {
		t.Fatalf("Expected event to be NewAssetEvent, got %T", bus.Published[0])
	}
	if event.FirstSeen != "ip" || event.Value != "10.0.0.1" {
		t.Errorf("Unexpected event payload: %+v", event)
	}

	// 2. Subsequent signal for the SAME asset -> Should NOT emit event
	sig2 := &testSignal{sigType: "ip", value: "10.0.0.1", conf: 1.0}
	_, err = resolver.Resolve(ctx, sig2)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(bus.Published) != 1 {
		t.Errorf("Event fired again! Expected 1 total event, got %d", len(bus.Published))
	}
}
