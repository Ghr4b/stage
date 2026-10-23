package container

import (
	"tijeri/internal/assets"
)

type ContainerSignalEvent struct {
	ImageDigest     string            `json:"image_digest"`
	ImageTags       []string          `json:"image_tags"`
	SourceRepo      string            `json:"source_repo,omitempty"` // From org.opencontainers.image.source
	Labels          map[string]string `json:"labels"`
	ConfidenceScore float64           `json:"confidence"`
	Source          string            `json:"source"` // "registry", "runtime"
}

// Ensure ContainerSignalEvent implements assets.IdentitySignal
var _ assets.IdentitySignal = (*ContainerSignalEvent)(nil)

func (s *ContainerSignalEvent) SignalType() string {
	return "image_digest"
}

func (s *ContainerSignalEvent) Value() string {
	return s.ImageDigest
}

func (s *ContainerSignalEvent) Confidence() float64 {
	return s.ConfidenceScore
}
