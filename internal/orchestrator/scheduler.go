package orchestrator

import (
	"tijeri/internal/models"
	"time"
)

// ScanJob represents a requested scan operation.
type ScanJob struct {
	Asset      models.Asset
	Trigger    string // "push", "nightly", "passive", "active"
	QueuedAt   time.Time
}

// Window defines a permitted time range for active scans.
type Window struct {
	StartHour int
	EndHour   int
}

// Scheduler handles the execution timing of scan jobs.
type Scheduler struct {
	ProductionWindow Window
	nowFunc          func() time.Time
}

func NewScheduler(nowFunc func() time.Time) *Scheduler {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return &Scheduler{
		ProductionWindow: Window{StartHour: 0, EndHour: 6}, // Default 00:00 to 06:00
		nowFunc:          nowFunc,
	}
}

// ShouldRunNow evaluates if a job can be executed immediately or must be deferred.
func (s *Scheduler) ShouldRunNow(job ScanJob) bool {
	// Passive signals are never gated
	if job.Trigger == "passive" {
		return true
	}

	// Active production scans are gated by maintenance windows
	isProduction := false
	if env, ok := job.Asset.Metadata["environment"]; ok && env == "production" {
		isProduction = true
	}

	if isProduction && job.Trigger == "active" {
		now := s.nowFunc()
		hour := now.Hour()
		
		// Handle overnight windows (e.g., 22:00 to 04:00)
		if s.ProductionWindow.StartHour > s.ProductionWindow.EndHour {
			inWindow := hour >= s.ProductionWindow.StartHour || hour < s.ProductionWindow.EndHour
			if !inWindow {
				return false
			}
		} else {
			inWindow := hour >= s.ProductionWindow.StartHour && hour < s.ProductionWindow.EndHour
			if !inWindow {
				return false
			}
		}
	}

	return true
}

// Triggers is a simulated log for demonstrating independent trigger tracking
// to satisfy integration testing requirements without full event bus setup.
type TriggerLog struct {
	Triggers []string
}

func (t *TriggerLog) Record(job ScanJob) {
	t.Triggers = append(t.Triggers, job.Trigger)
}
