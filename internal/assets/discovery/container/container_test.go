package container

import (
	"context"
	"testing"
)

func TestRegistryWebhookDigestExtraction(t *testing.T) {
	handler := &RegistryWebhookHandler{}
	
	// Fixture
	payload := []byte(`{
		"action": "push",
		"target": {
			"digest": "sha256:1234567890abcdef",
			"tag": "latest",
			"repository": "my-app"
		},
		"labels": {
			"org.opencontainers.image.source": "https://github.com/my-org/my-app"
		}
	}`)

	sig, err := handler.ProcessEvent(context.Background(), payload)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sig.ImageDigest != "sha256:1234567890abcdef" {
		t.Errorf("Incorrect digest extracted: %s", sig.ImageDigest)
	}

	if sig.SourceRepo != "https://github.com/my-org/my-app" {
		t.Errorf("Incorrect OCI source repo extracted: %s", sig.SourceRepo)
	}
}

func TestRuntimeWatcherIdentityResolution(t *testing.T) {
	watcher := &RuntimeWatcher{}

	// K8s pod event
	event := PodEvent{
		PodName:        "my-app-deployment-559d658b74-12345",
		Namespace:      "default",
		ContainerImage: "nginx:latest@sha256:abcdef1234567890",
	}

	sig, err := watcher.ProcessPodEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Assert that it resolves to an image-digest identity, never a pod-name identity
	if sig.SignalType() != "image_digest" {
		t.Errorf("Expected identity type image_digest, got %s", sig.SignalType())
	}

	if sig.Value() == event.PodName {
		t.Errorf("CRITICAL VIOLATION (I13): Signal resolved to pod-name identity instead of image-digest!")
	}

	if sig.Value() != "sha256:abcdef1234567890" {
		t.Errorf("Expected value to be digest sha256:abcdef1234567890, got %s", sig.Value())
	}
}
