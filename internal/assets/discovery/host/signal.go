package host

import (
	"tijeri/internal/assets"
)

type HostSignalEvent struct {
	Type            string  `json:"signal_type"` // e.g. "mac_address", "ip", "fqdn"
	HostValue       string  `json:"value"`
	ConfidenceScore float64 `json:"confidence"`
	Source          string  `json:"source"` // "active", "passive", "agent"
}

// Ensure HostSignalEvent implements assets.IdentitySignal
var _ assets.IdentitySignal = (*HostSignalEvent)(nil)

func (s *HostSignalEvent) SignalType() string {
	return s.Type
}

func (s *HostSignalEvent) Value() string {
	return s.HostValue
}

func (s *HostSignalEvent) Confidence() float64 {
	return s.ConfidenceScore
}
