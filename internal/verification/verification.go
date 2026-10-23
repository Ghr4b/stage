package verification

import (
	"context"
	"encoding/json"
	"time"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

type RescanJob struct {
	AssetID   string
	Component string
	RunAt     time.Time
}

// ScheduleRescan creates a targeted rescan job 24-48 hours after resolution.
func ScheduleRescan(f models.Finding, resolvedAt time.Time) RescanJob {
	return RescanJob{
		AssetID:   f.AssetID,
		Component: f.Component,
		RunAt:     resolvedAt.Add(36 * time.Hour), // 36 hours is right in the 24-48h window
	}
}

// HandleRecurrence processes a finding that was found again during a targeted rescan.
func HandleRecurrence(ctx context.Context, ticketID string, adapter remediation.TicketingAdapter) error {
	return adapter.UpdateTicket(ctx, ticketID, models.TicketUpdate{
		Status: "reopened",
		Note:   "Automated verification failed: Vulnerability still present on targeted rescan. Reopening original ticket.",
	})
}

// RecurrenceFeedback represents the schema payload for Phase 11.
type RecurrenceFeedback struct {
	FindingID            string    `json:"finding_id"`
	AssetID              string    `json:"asset_id"`
	VulnerabilityID      string    `json:"vulnerability_id"`
	BODTierAtResolution  int       `json:"bod_tier_at_resolution"`
	EPSSAtResolution     float64   `json:"epss_at_resolution,omitempty"`
	ResolvedAt           time.Time `json:"resolved_at"`
	RecurrenceDetectedAt time.Time `json:"recurrence_detected_at"`
	Component            string    `json:"component,omitempty"`
	ComponentVersion     string    `json:"component_version,omitempty"`
}

// EmitRecurrenceFeedback creates the JSON payload for the feedback signal.
func EmitRecurrenceFeedback(f models.Finding, resolvedAt, detectedAt time.Time, bodTier int) ([]byte, error) {
	epss := 0.0
	if f.EPSS != nil {
		epss = f.EPSS.Score
	}
	
	payload := RecurrenceFeedback{
		FindingID:            f.FindingID,
		AssetID:              f.AssetID,
		VulnerabilityID:      f.VulnerabilityID,
		BODTierAtResolution:  bodTier,
		EPSSAtResolution:     epss,
		ResolvedAt:           resolvedAt,
		RecurrenceDetectedAt: detectedAt,
		Component:            f.Component,
		ComponentVersion:     f.ComponentVersion,
	}
	
	return json.Marshal(payload)
}

// DriftMetric computes the "fixed actually means fixed" rate (1.0 - recurrence_rate)
func DriftMetric(totalResolved, totalRecurred int) float64 {
	if totalResolved == 0 {
		return 1.0
	}
	recurrenceRate := float64(totalRecurred) / float64(totalResolved)
	return 1.0 - recurrenceRate
}
