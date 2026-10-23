package orchestrator

import (
	"context"
	"strings"
	"tijeri/internal/models"
)

// Router determines which ScannerAdapters should run for a given asset.
type Router struct {
	Adapters []ScannerAdapter
}

// ScannerAdapter is a local re-declaration for orchestrator routing logic,
// aligning with the global ScannerAdapter interface.
type ScannerAdapter interface {
	Supports(asset models.Asset) bool
	Name() string
}

// NewRouter initializes a Router with a set of adapters.
func NewRouter(adapters []ScannerAdapter) *Router {
	return &Router{Adapters: adapters}
}

// Route returns the list of adapter names that should be executed for the given asset.
func (r *Router) Route(ctx context.Context, asset models.Asset) []string {
	var matches []string

	// Check if this is a repository asset with multiple languages
	manifestCount := 0
	if repoTags, ok := asset.Metadata["ecosystems"]; ok {
		tags := strings.Split(repoTags, ",")
		for _, tag := range tags {
			if isScaManifest(strings.TrimSpace(tag)) {
				manifestCount++
			}
		}
	}

	for _, adapter := range r.Adapters {
		// Multi-language routing logic: if a repo has >1 language, route to OSV-Scanner V2
		// instead of individual ecosystem scanners.
		if isIndividualScaAdapter(adapter.Name()) && manifestCount > 1 {
			continue // Skip individual ecosystem scanners
		}
		if adapter.Name() == "osv-scanner" && manifestCount <= 1 {
			continue // Skip OSV-Scanner if it's not multi-language
		}

		if adapter.Supports(asset) {
			matches = append(matches, adapter.Name())
		}
	}

	return matches
}

func isScaManifest(tag string) bool {
	switch tag {
	case "python", "go", "node", "rust", "ruby":
		return true
	}
	return false
}

func isIndividualScaAdapter(name string) bool {
	switch name {
	case "uv audit", "govulncheck", "npm audit", "cargo audit", "bundler-audit":
		return true
	}
	return false
}
