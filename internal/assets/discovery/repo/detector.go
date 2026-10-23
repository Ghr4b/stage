package repo

import (
	"strings"
)

var ManifestToEcosystem = map[string]string{
	"package.json":   "npm",
	"go.mod":         "go",
	"pyproject.toml": "pypi",
	"Cargo.toml":     "cargo",
	"Gemfile":        "rubygems",
	"Dockerfile":     "docker",
}

// DetectEcosystems takes a list of filenames in a repository and returns the unique ecosystems detected.
func DetectEcosystems(filenames []string) []string {
	ecosystemSet := make(map[string]bool)
	for _, filename := range filenames {
		// Just match the exact filename for now, though we could match paths if needed.
		// GitHub webhooks sometimes provide added/modified files as paths e.g., "src/package.json"
		parts := strings.Split(filename, "/")
		baseName := parts[len(parts)-1]

		if eco, ok := ManifestToEcosystem[baseName]; ok {
			ecosystemSet[eco] = true
		}
	}

	var ecosystems []string
	for eco := range ecosystemSet {
		ecosystems = append(ecosystems, eco)
	}
	return ecosystems
}
