package remediation

import (
	"context"
	"testing"
	"time"
	"tijeri/internal/models"
)

type MockAdapter struct {
	Closed bool
	Assigned bool
	Escalated bool
}

func (m *MockAdapter) Name() string { return "mock" }
func (m *MockAdapter) CreateTicket(ctx context.Context, f models.Finding) (string, error) { return "1", nil }
func (m *MockAdapter) UpdateTicket(ctx context.Context, ticketID string, update models.TicketUpdate) error {
	if update.Status == "assigned" { m.Assigned = true }
	if update.Status == "escalated" { m.Escalated = true }
	return nil
}
func (m *MockAdapter) CloseTicket(ctx context.Context, ticketID string, reason string) error {
	m.Closed = true
	return nil
}

func TestEliminationPolicies(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	breachTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	
	t.Run("AutoClose", func(t *testing.T) {
		adapter := &MockAdapter{}
		AutoClose(ctx, "1", adapter, false)
		if adapter.Closed { t.Error("Should not close unpatched ticket") }
		
		AutoClose(ctx, "1", adapter, true)
		if !adapter.Closed { t.Error("Should close patched ticket") }
	})
	
	t.Run("AutoAssign", func(t *testing.T) {
		adapter := &MockAdapter{}
		AutoAssign(ctx, "1", adapter, "team-sec")
		if !adapter.Assigned { t.Error("Should auto-assign ticket") }
	})
	
	t.Run("AutoEscalate", func(t *testing.T) {
		adapter := &MockAdapter{}
		
		// Early
		AutoEscalate(ctx, "1", adapter, breachTime, now)
		if adapter.Escalated { t.Error("Should not escalate early") }
		
		// Exact time
		AutoEscalate(ctx, "1", adapter, breachTime, breachTime)
		if !adapter.Escalated { t.Error("Should escalate exactly at breach time") }
	})
}

func TestEscalationCadence(t *testing.T) {
	breachTime := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	interval := 24 * time.Hour
	
	// Early -> 0
	if alerts := EscalationCadence(breachTime, breachTime.Add(-1*time.Hour), interval); alerts != 0 {
		t.Errorf("Expected 0 alerts before breach, got %d", alerts)
	}
	
	// Exact breach -> 1
	if alerts := EscalationCadence(breachTime, breachTime, interval); alerts != 1 {
		t.Errorf("Expected 1 alert at breach, got %d", alerts)
	}
	
	// 2.5 days past breach -> 3 alerts (at breach, +24h, +48h)
	if alerts := EscalationCadence(breachTime, breachTime.Add(60*time.Hour), interval); alerts != 3 {
		t.Errorf("Expected 3 alerts 2.5 days past breach, got %d", alerts)
	}
}
