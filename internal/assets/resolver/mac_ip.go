package resolver

import (
	"math"
	"time"
)

// ConfidenceDecay computes the time-decayed confidence for an IP-based match.
// At t=0, confidence = baseConfidence. The confidence monotonically decreases
// towards 0 as timeDelta increases, reaching ~0 at 90 days.
func ConfidenceDecay(baseConfidence float64, timeDelta time.Duration) float64 {
	days := timeDelta.Hours() / 24.0
	if days <= 0 {
		return baseConfidence
	}
	// Exponential decay: halfLife = 15 days
	halfLife := 15.0
	decay := math.Pow(0.5, days/halfLife)
	return baseConfidence * decay
}

// IsMACOrIP returns true if a signal type is MAC or IP.
// These must NEVER appear in the deterministic tier (invariant I2).
func IsMACOrIP(signalType string) bool {
	return signalType == "mac_address" || signalType == "ip"
}
