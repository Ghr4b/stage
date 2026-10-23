package container

import (
	"context"
	"strings"
)

type RuntimeWatcher struct {
	Publisher Publisher
}

// PodEvent simulates a simplified k8s pod event
type PodEvent struct {
	PodName        string
	Namespace      string
	ContainerImage string // e.g. "nginx:latest@sha256:123456..."
}

func (w *RuntimeWatcher) ProcessPodEvent(ctx context.Context, event PodEvent) (ContainerSignalEvent, error) {
	// A running pod's signal MUST resolve to an image-digest identity, never a pod-name identity.
	// We extract the digest from the image string.
	
	digest := ""
	parts := strings.Split(event.ContainerImage, "@")
	if len(parts) > 1 {
		digest = parts[1]
	} else {
		// If no digest, we might hash the image tag or resolve it against registry (mocked here as using the full image string as fallback)
		digest = event.ContainerImage 
	}

	sig := ContainerSignalEvent{
		ImageDigest:     digest,
		ConfidenceScore: 1.0,
		Source:          "runtime",
	}

	return sig, nil
}
