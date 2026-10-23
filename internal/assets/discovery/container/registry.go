package container

import (
	"context"
	"encoding/json"
)

type RegistryWebhookHandler struct {
	Publisher Publisher
}

type Publisher interface {
	Publish(subject string, data []byte) error
}

type RegistryEvent struct {
	Action string `json:"action"`
	Target struct {
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
		Repository string `json:"repository"`
	} `json:"target"`
	Labels map[string]string `json:"labels"` // Simplified for test
}

func (h *RegistryWebhookHandler) ProcessEvent(ctx context.Context, payload []byte) (ContainerSignalEvent, error) {
	var event RegistryEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return ContainerSignalEvent{}, err
	}

	sig := ContainerSignalEvent{
		ImageDigest:     event.Target.Digest,
		ImageTags:       []string{event.Target.Tag},
		Labels:          event.Labels,
		ConfidenceScore: 1.0,
		Source:          "registry",
	}

	if src, ok := event.Labels["org.opencontainers.image.source"]; ok {
		sig.SourceRepo = src
	}

	return sig, nil
}
