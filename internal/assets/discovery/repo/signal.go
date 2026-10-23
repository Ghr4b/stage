package repo

import (
	"tijeri/internal/assets"
)

type RepoSignalEvent struct {
	Type            string   `json:"signal_type"`
	URL             string   `json:"value"`
	ConfidenceScore float64  `json:"confidence"`
	Ecosystems      []string `json:"ecosystems"`
}

// Ensure RepoSignalEvent implements assets.IdentitySignal
var _ assets.IdentitySignal = (*RepoSignalEvent)(nil)

func (s *RepoSignalEvent) SignalType() string {
	return s.Type
}

func (s *RepoSignalEvent) Value() string {
	return s.URL
}

func (s *RepoSignalEvent) Confidence() float64 {
	return s.ConfidenceScore
}
