package orchestrator

import (
	"errors"
	"strings"
)

// ValidateImageReference ensures an image reference uses an immutable digest
// rather than a mutable tag.
// e.g. "nginx@sha256:abcd..." is allowed
// "nginx:latest" is rejected
func ValidateImageReference(image string) error {
	if strings.Contains(image, "@sha256:") {
		return nil
	}
	return errors.New("image reference must use an immutable sha256 digest, mutable tags are forbidden")
}

// AdapterConfig represents a scanner configuration for checking
type AdapterConfig struct {
	Name  string
	Image string
}

// CheckAllConfigs validates a list of adapter configurations to enforce digest pinning.
func CheckAllConfigs(configs []AdapterConfig) []error {
	var errs []error
	for _, cfg := range configs {
		if err := ValidateImageReference(cfg.Image); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
