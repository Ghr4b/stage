package directory

import (
	"tijeri/internal/assets"
)

type DirectorySignalEvent struct {
	ObjectSID       string            `json:"object_sid"` // Primary key
	Hostname        string            `json:"hostname,omitempty"`
	Attributes      map[string]string `json:"attributes,omitempty"`
	ConfidenceScore float64           `json:"confidence"`
	Source          string            `json:"source"` // e.g. "active_directory"
}

// Ensure DirectorySignalEvent implements assets.IdentitySignal
var _ assets.IdentitySignal = (*DirectorySignalEvent)(nil)

func (s *DirectorySignalEvent) SignalType() string {
	return "domain_sid"
}

func (s *DirectorySignalEvent) Value() string {
	return s.ObjectSID
}

func (s *DirectorySignalEvent) Confidence() float64 {
	return s.ConfidenceScore
}
