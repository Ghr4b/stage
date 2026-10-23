package remediation

import (
	"time"
)

type TicketHistory struct {
	TicketID   string
	BODTier    int
	CreatedAt  time.Time
	ResolvedAt *time.Time
	SLA        int // Days
}

// ComputeMTTR computes Mean Time To Resolution by BOD Tier in days.
func ComputeMTTR(history []TicketHistory) map[int]float64 {
	sums := make(map[int]float64)
	counts := make(map[int]int)
	
	for _, t := range history {
		if t.ResolvedAt != nil {
			durationDays := t.ResolvedAt.Sub(t.CreatedAt).Hours() / 24.0
			sums[t.BODTier] += durationDays
			counts[t.BODTier]++
		}
	}
	
	mttr := make(map[int]float64)
	for tier, count := range counts {
		mttr[tier] = sums[tier] / float64(count)
	}
	
	return mttr
}

// CountOpenPastSLA counts how many open tickets have breached their SLA.
func CountOpenPastSLA(history []TicketHistory, now time.Time) int {
	count := 0
	for _, t := range history {
		if t.ResolvedAt == nil {
			deadline := t.CreatedAt.Add(time.Duration(t.SLA) * 24 * time.Hour)
			if now.After(deadline) {
				count++
			}
		}
	}
	return count
}

// ComputeEliminationRate computes the percentage of tickets opened in a window that were resolved.
func ComputeEliminationRate(history []TicketHistory, windowStart, windowEnd time.Time) float64 {
	opened := 0
	resolved := 0
	
	for _, t := range history {
		if t.CreatedAt.After(windowStart) && t.CreatedAt.Before(windowEnd) {
			opened++
			if t.ResolvedAt != nil {
				resolved++
			}
		}
	}
	
	if opened == 0 {
		return 0.0
	}
	return float64(resolved) / float64(opened)
}
