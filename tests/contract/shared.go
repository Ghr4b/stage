package contract

import (
	"context"
	"testing"
	"tijeri/internal/models"
	"tijeri/internal/remediation"
)

// RunTicketingAdapterContract verifies a TicketingAdapter implementation
// behaves correctly under successful conditions.
func RunTicketingAdapterContract(t *testing.T, adapter remediation.TicketingAdapter) {
	ctx := context.Background()
	finding := models.Finding{FindingID: "f-1", VulnerabilityID: "CVE-TEST"}
	
	// Create
	id, err := adapter.CreateTicket(ctx, finding)
	if err != nil {
		t.Fatalf("[%s] Unexpected error creating ticket: %v", adapter.Name(), err)
	}
	if id == "" {
		t.Fatalf("[%s] Expected valid ticket ID, got empty string", adapter.Name())
	}
	
	// Update
	err = adapter.UpdateTicket(ctx, id, models.TicketUpdate{Status: "in-progress"})
	if err != nil {
		t.Errorf("[%s] Unexpected error updating ticket: %v", adapter.Name(), err)
	}
	
	// Close
	err = adapter.CloseTicket(ctx, id, "resolved")
	if err != nil {
		t.Errorf("[%s] Unexpected error closing ticket: %v", adapter.Name(), err)
	}
}
