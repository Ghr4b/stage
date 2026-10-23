package remediation

import (
	"testing"
	"time"
)

func TestKPIs(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC) // 2 days later
	t4 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC) // 4 days later
	
	history := []TicketHistory{
		// Resolved in 2 days, Tier 3, SLA 3
		{TicketID: "1", BODTier: 3, CreatedAt: t1, ResolvedAt: &t2, SLA: 3},
		// Resolved in 4 days, Tier 3, SLA 3
		{TicketID: "2", BODTier: 3, CreatedAt: t1, ResolvedAt: &t4, SLA: 3},
		// Unresolved, past SLA 3
		{TicketID: "3", BODTier: 3, CreatedAt: t1, ResolvedAt: nil, SLA: 3},
		// Unresolved, not past SLA 14
		{TicketID: "4", BODTier: 14, CreatedAt: t1, ResolvedAt: nil, SLA: 14},
	}
	
	now := time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC) // 5 days after t1
	
	// MTTR for Tier 3 should be (2 + 4) / 2 = 3.0 days
	mttr := ComputeMTTR(history)
	if mttr[3] != 3.0 {
		t.Errorf("Expected MTTR for Tier 3 to be 3.0, got %.2f", mttr[3])
	}
	
	// Open past SLA: Ticket 3 is past its 3-day SLA. Ticket 4 is within its 14-day SLA. -> 1
	breached := CountOpenPastSLA(history, now)
	if breached != 1 {
		t.Errorf("Expected 1 ticket past SLA, got %d", breached)
	}
	
	// Elimination rate: 4 opened, 2 resolved -> 50%
	rate := ComputeEliminationRate(history, time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC))
	if rate != 0.5 {
		t.Errorf("Expected 0.5 elimination rate, got %.2f", rate)
	}
}
