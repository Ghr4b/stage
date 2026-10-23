package verification

import (
	"context"
	"encoding/json"
	"testing"
	"time"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
	
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestScheduledTargetedRescan(t *testing.T) {
	f := models.Finding{
		AssetID: "asset-1",
		Component: "openssl",
	}
	resolvedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	
	job := ScheduleRescan(f, resolvedAt)
	
	if job.AssetID != "asset-1" || job.Component != "openssl" {
		t.Errorf("Job scope is not correctly targeted. Got %+v", job)
	}
	
	diffHours := job.RunAt.Sub(resolvedAt).Hours()
	if diffHours < 24 || diffHours > 48 {
		t.Errorf("Scheduled delay not in 24-48h window. Got %f hours", diffHours)
	}
}

type MockTicketingAdapter struct {
	remediation.TicketingAdapter // embedding to satisfy interface without implementing all methods
	Updates []models.TicketUpdate
}
func (m *MockTicketingAdapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	m.Updates = append(m.Updates, update)
	return nil
}

// Named test (I13 recurrence handling)
func TestRecurrenceReopensOriginalTicketNotDuplicate(t *testing.T) {
	adapter := &MockTicketingAdapter{}
	ticketID := "TICKET-123"
	
	err := HandleRecurrence(context.Background(), ticketID, adapter)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if len(adapter.Updates) != 1 {
		t.Fatalf("Expected 1 update, got %d", len(adapter.Updates))
	}
	
	update := adapter.Updates[0]
	if update.Status != "reopened" {
		t.Errorf("Expected status 'reopened', got '%s'", update.Status)
	}
	if update.Note == "" {
		t.Error("Expected explanation note, got empty")
	}
}

func TestDriftMetric(t *testing.T) {
	// 10 resolved, 2 recurred -> recurrence rate 0.2 -> drift metric (fixed means fixed) 0.8
	metric := DriftMetric(10, 2)
	if metric != 0.8 {
		t.Errorf("Expected 0.8, got %f", metric)
	}
}

func TestFeedbackSignalSchema(t *testing.T) {
	f := models.Finding{
		FindingID: "f-1",
		AssetID: "a-1",
		VulnerabilityID: "CVE-2023-1111",
		Component: "log4j",
	}
	
	resolvedAt := time.Now()
	detectedAt := resolvedAt.Add(40 * time.Hour)
	
	payload, err := EmitRecurrenceFeedback(f, resolvedAt, detectedAt, 14)
	if err != nil {
		t.Fatalf("Failed to emit feedback: %v", err)
	}
	
	compiler := jsonschema.NewCompiler()
	sch, err := compiler.Compile("../../schemas/recurrence_feedback.schema.json")
	if err != nil {
		t.Fatalf("Failed to compile schema: %v", err)
	}
	
	var v interface{}
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}
	
	if err := sch.Validate(v); err != nil {
		t.Errorf("Payload failed schema validation: %v", err)
	}
}
