package orchestrator

import (
	"context"
	"strings"
	"testing"
	"tijeri/internal/models"
)

type mockAdapter struct {
	name        string
	supportFunc func(asset models.Asset) bool
}

func (m mockAdapter) Name() string                     { return m.name }
func (m mockAdapter) Supports(asset models.Asset) bool { return m.supportFunc(asset) }

func hasMetadataValue(asset models.Asset, key, expected string) bool {
	val, ok := asset.Metadata[key]
	if !ok {
		return false
	}
	return val == expected || (key == "ecosystems" && containsTag(val, expected))
}

func containsTag(tagsStr, target string) bool {
	for _, t := range strings.Split(tagsStr, ",") {
		if strings.TrimSpace(t) == target {
			return true
		}
	}
	return false
}

func TestRoutingTable(t *testing.T) {
	adapters := []ScannerAdapter{
		mockAdapter{"network-scanner", func(a models.Asset) bool { return a.Type == "host" }},
		mockAdapter{"uv audit", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "python") }},
		mockAdapter{"govulncheck", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "go") }},
		mockAdapter{"npm audit", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "node") }},
		mockAdapter{"cargo audit", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "rust") }},
		mockAdapter{"bundler-audit", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "ruby") }},
		mockAdapter{"osv-scanner", func(a models.Asset) bool { return hasMetadataValue(a, "type", "repo") }}, // Supports() check is broad, Router logic restricts it
		mockAdapter{"container-scanner", func(a models.Asset) bool { return hasMetadataValue(a, "ecosystems", "docker") }},
	}

	router := NewRouter(adapters)
	ctx := context.Background()

	testCases := []struct {
		name         string
		asset        models.Asset
		wantAdapters []string
	}{
		{
			name:         "host -> network scanner",
			asset:        models.Asset{Type: "host"},
			wantAdapters: []string{"network-scanner"},
		},
		{
			name:         "pyproject.toml/uv.lock -> uv audit",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "python"}},
			wantAdapters: []string{"uv audit"},
		},
		{
			name:         "go.mod -> govulncheck",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "go"}},
			wantAdapters: []string{"govulncheck"},
		},
		{
			name:         "package.json -> npm audit",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "node"}},
			wantAdapters: []string{"npm audit"},
		},
		{
			name:         "Cargo.toml -> cargo audit",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "rust"}},
			wantAdapters: []string{"cargo audit"},
		},
		{
			name:         "Gemfile -> bundler-audit",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "ruby"}},
			wantAdapters: []string{"bundler-audit"},
		},
		{
			name:         "multi-language -> OSV-Scanner V2",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "node, go"}},
			wantAdapters: []string{"osv-scanner"},
		},
		{
			name:         "repo with both package.json and Dockerfile -> SCA and container adapters",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "node, docker"}},
			wantAdapters: []string{"npm audit", "container-scanner"},
		},
		{
			name:         "repo with multiple SCA and Dockerfile",
			asset:        models.Asset{Type: "repo", Metadata: map[string]string{"type": "repo", "ecosystems": "node, python, docker"}},
			wantAdapters: []string{"osv-scanner", "container-scanner"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := router.Route(ctx, tc.asset)
			
			if len(got) != len(tc.wantAdapters) {
				t.Fatalf("Got %d adapters %v, want %d %v", len(got), got, len(tc.wantAdapters), tc.wantAdapters)
			}
			
			for i, a := range tc.wantAdapters {
				if got[i] != a {
					t.Errorf("At index %d: got %s, want %s", i, got[i], a)
				}
			}
		})
	}
}
