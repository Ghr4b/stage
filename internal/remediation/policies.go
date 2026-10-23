package remediation

import (
	"context"
	"time"
	"tijeri/internal/models"
)

// AutoClose closes the ticket if a patch is confirmed via rescan or CDB flip.
func AutoClose(ctx context.Context, ticketID string, adapter TicketingAdapter, isPatched bool) error {
	if isPatched {
		return adapter.CloseTicket(ctx, ticketID, "Automated close: confirmed patched")
	}
	return nil
}

// AutoAssign updates the ticket assignment at creation time.
func AutoAssign(ctx context.Context, ticketID string, adapter TicketingAdapter, owner string) error {
	// Typically this would set the assignee in the ticketing system.
	// We'll simulate by updating the ticket status/notes.
	return adapter.UpdateTicket(ctx, ticketID, models.TicketUpdate{
		Status: "assigned",
		Note:   "Assigned to " + owner,
	})
}

// AutoEscalate escalates the ticket if the SLA breach time has passed.
func AutoEscalate(ctx context.Context, ticketID string, adapter TicketingAdapter, breachTime time.Time, now time.Time) error {
	if now.After(breachTime) || now.Equal(breachTime) {
		return adapter.UpdateTicket(ctx, ticketID, models.TicketUpdate{
			Status: "escalated",
			Note:   "Automated escalation: SLA breached",
		})
	}
	return nil
}

// EscalationCadence fires repeated alerts (e.g. to Slack/email) for tickets past their SLA.
// It computes how many intervals have passed since breach to determine how many alerts should have fired.
// In a real system, this would be a stateful check.
func EscalationCadence(breachTime time.Time, now time.Time, interval time.Duration) int {
	if now.Before(breachTime) {
		return 0
	}
	
	durationPastBreach := now.Sub(breachTime)
	alerts := int(durationPastBreach / interval) + 1 // +1 for the immediate breach alert
	
	return alerts
}
