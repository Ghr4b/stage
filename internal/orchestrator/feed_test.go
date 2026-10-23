package orchestrator

import (
	"context"
	"testing"
	"time"
)

type mockPuller struct {
	pullCount int
}

func (m *mockPuller) Pull(ctx context.Context) error {
	m.pullCount++
	return nil
}

func TestFeedConfigValidation(t *testing.T) {
	t.Run("Rejects AlwaysPullHEAD", func(t *testing.T) {
		cfg := FeedConfig{
			AdapterName:    "nuclei",
			UpdateInterval: 24 * time.Hour,
			AlwaysPullHEAD: true,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Expected error for AlwaysPullHEAD=true")
		}
	})

	t.Run("Rejects excessively short intervals", func(t *testing.T) {
		cfg := FeedConfig{
			AdapterName:    "nuclei",
			UpdateInterval: 5 * time.Minute,
		}
		if err := cfg.Validate(); err == nil {
			t.Error("Expected error for interval < 1 hour")
		}
	})

	t.Run("Accepts valid config", func(t *testing.T) {
		cfg := FeedConfig{
			AdapterName:    "nuclei",
			UpdateInterval: 24 * time.Hour,
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("Expected valid config to pass, got %v", err)
		}
	})
}

func TestFeedManagerCadence(t *testing.T) {
	currentTime := time.Now()
	nowFunc := func() time.Time {
		return currentTime
	}

	manager := NewFeedManager(nowFunc)
	puller := &mockPuller{}
	
	cfg := FeedConfig{
		AdapterName:    "openvas",
		UpdateInterval: 24 * time.Hour,
	}
	
	if err := manager.Register(cfg, puller); err != nil {
		t.Fatalf("Failed to register config: %v", err)
	}

	ctx := context.Background()

	// 1. Initial job: Should trigger a pull
	_ = manager.EnsureUpToDate(ctx, "openvas")
	if puller.pullCount != 1 {
		t.Fatalf("Expected 1 pull initially, got %d", puller.pullCount)
	}

	// 2. Second job right after: Should NOT trigger a pull
	_ = manager.EnsureUpToDate(ctx, "openvas")
	if puller.pullCount != 1 {
		t.Errorf("Expected pull count to remain 1, got %d", puller.pullCount)
	}

	// 3. Fast forward time by 12 hours (within window): Should NOT trigger a pull
	currentTime = currentTime.Add(12 * time.Hour)
	_ = manager.EnsureUpToDate(ctx, "openvas")
	if puller.pullCount != 1 {
		t.Errorf("Expected pull count to remain 1 after 12h, got %d", puller.pullCount)
	}

	// 4. Fast forward time past 24 hour interval: SHOULD trigger a pull
	currentTime = currentTime.Add(13 * time.Hour) // Total 25 hours elapsed
	_ = manager.EnsureUpToDate(ctx, "openvas")
	if puller.pullCount != 2 {
		t.Errorf("Expected pull count to be 2 after 25h, got %d", puller.pullCount)
	}
}
