package wazuh

import (
	"tijeri/internal/assets"
)

type WazuhSignalEvent struct {
	AgentID         string   `json:"agent_id"`
	AgentName       string   `json:"agent_name"`
	AgentIP         string   `json:"agent_ip"`
	MACAddress      string   `json:"mac_address,omitempty"`
	OSName          string   `json:"os_name,omitempty"`
	Packages        []string `json:"packages,omitempty"`
	ConfidenceScore float64  `json:"confidence"`
	Source          string   `json:"source"` // "wazuh"
}

// Ensure WazuhSignalEvent implements assets.IdentitySignal
var _ assets.IdentitySignal = (*WazuhSignalEvent)(nil)

func (s *WazuhSignalEvent) SignalType() string {
	return "wazuh_agent"
}

func (s *WazuhSignalEvent) Value() string {
	return s.AgentID
}

func (s *WazuhSignalEvent) Confidence() float64 {
	return s.ConfidenceScore
}
