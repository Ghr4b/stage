package orchestrator

import (
	"testing"
)

func TestDigestPinningEnforcement(t *testing.T) {
	t.Run("Passes on valid digest", func(t *testing.T) {
		cfg := AdapterConfig{
			Name:  "govulncheck-adapter",
			Image: "golang@sha256:b1d5bf958eabf828a1c97a5c889fdf55f054f15d7e5d89f417f53f93c0dae858",
		}
		err := ValidateImageReference(cfg.Image)
		if err != nil {
			t.Errorf("Expected valid digest to pass, got error: %v", err)
		}
	})

	t.Run("Fails on mutable tag (latest)", func(t *testing.T) {
		cfg := AdapterConfig{
			Name:  "trivy-adapter",
			Image: "aquasec/trivy:latest",
		}
		err := ValidateImageReference(cfg.Image)
		if err == nil {
			t.Error("Expected mutable tag :latest to fail validation, but it passed")
		}
	})

	t.Run("Fails on implicit latest (no tag)", func(t *testing.T) {
		cfg := AdapterConfig{
			Name:  "trivy-adapter",
			Image: "aquasec/trivy",
		}
		err := ValidateImageReference(cfg.Image)
		if err == nil {
			t.Error("Expected implicit latest tag to fail validation, but it passed")
		}
	})

	t.Run("Fails on version tag", func(t *testing.T) {
		cfg := AdapterConfig{
			Name:  "trivy-adapter",
			Image: "aquasec/trivy:v0.40.0",
		}
		err := ValidateImageReference(cfg.Image)
		if err == nil {
			t.Error("Expected version tag to fail validation, but it passed")
		}
	})
	
	t.Run("Batch check catches multiple errors", func(t *testing.T) {
		configs := []AdapterConfig{
			{Name: "valid", Image: "alpine@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
			{Name: "invalid-1", Image: "alpine:latest"},
			{Name: "invalid-2", Image: "alpine"},
		}
		
		errs := CheckAllConfigs(configs)
		if len(errs) != 2 {
			t.Errorf("Expected 2 errors from CheckAllConfigs, got %d", len(errs))
		}
	})
}
