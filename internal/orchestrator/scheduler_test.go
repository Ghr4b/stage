package orchestrator

import (
	"tijeri/internal/models"
	"testing"
	"time"
)

func TestSchedulingWindows(t *testing.T) {
	// Set current time to 12:00 PM (noon), which is outside the default 00:00 - 06:00 window
	mockTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nowFunc := func() time.Time { return mockTime }

	scheduler := NewScheduler(nowFunc)

	t.Run("Production host scan outside window is deferred", func(t *testing.T) {
		job := ScanJob{
			Asset: models.Asset{
				Type:     "host",
				Metadata: map[string]string{"environment": "production"},
			},
			Trigger: "active",
		}

		if scheduler.ShouldRunNow(job) {
			t.Error("Expected production active scan to be deferred outside window, but it ran")
		}
	})

	t.Run("Production host scan inside window runs", func(t *testing.T) {
		// Advance time to 02:00 AM (inside 00:00 - 06:00 window)
		scheduler.nowFunc = func() time.Time {
			return time.Date(2026, 1, 1, 2, 0, 0, 0, time.UTC)
		}

		job := ScanJob{
			Asset: models.Asset{
				Type:     "host",
				Metadata: map[string]string{"environment": "production"},
			},
			Trigger: "active",
		}

		if !scheduler.ShouldRunNow(job) {
			t.Error("Expected production active scan to run inside window, but it was deferred")
		}
	})

	t.Run("Passive signal processing is never gated by window", func(t *testing.T) {
		// Time is back to 12:00 PM (outside window)
		scheduler.nowFunc = nowFunc

		job := ScanJob{
			Asset: models.Asset{
				Type:     "host",
				Metadata: map[string]string{"environment": "production"},
			},
			Trigger: "passive",
		}

		if !scheduler.ShouldRunNow(job) {
			t.Error("Expected passive scan to run immediately regardless of window, but it was deferred")
		}
	})

	t.Run("SCA job fires on push and nightly sweep as distinct triggers", func(t *testing.T) {
		logger := &TriggerLog{}
		
		// Simulate a push event
		pushJob := ScanJob{
			Asset:   models.Asset{Type: "repo"},
			Trigger: "push",
		}
		if scheduler.ShouldRunNow(pushJob) {
			logger.Record(pushJob)
		}

		// Simulate a nightly sweep event
		nightlyJob := ScanJob{
			Asset:   models.Asset{Type: "repo"},
			Trigger: "nightly",
		}
		if scheduler.ShouldRunNow(nightlyJob) {
			logger.Record(nightlyJob)
		}

		if len(logger.Triggers) != 2 {
			t.Fatalf("Expected 2 distinct triggers, got %d", len(logger.Triggers))
		}
		if logger.Triggers[0] != "push" || logger.Triggers[1] != "nightly" {
			t.Errorf("Expected [push, nightly], got %v", logger.Triggers)
		}
	})
}
