package repo

import (
	"sort"
	"testing"
)

func TestDetectEcosystems(t *testing.T) {
	tests := []struct {
		name      string
		filenames []string
		expected  []string
	}{
		{
			name:      "npm manifest",
			filenames: []string{"package.json", "index.js"},
			expected:  []string{"npm"},
		},
		{
			name:      "go manifest",
			filenames: []string{"go.mod", "main.go"},
			expected:  []string{"go"},
		},
		{
			name:      "python manifest",
			filenames: []string{"pyproject.toml", "src/main.py"},
			expected:  []string{"pypi"},
		},
		{
			name:      "cargo manifest",
			filenames: []string{"Cargo.toml", "src/main.rs"},
			expected:  []string{"cargo"},
		},
		{
			name:      "rubygems manifest",
			filenames: []string{"Gemfile", "lib/main.rb"},
			expected:  []string{"rubygems"},
		},
		{
			name:      "multi-manifest repo",
			filenames: []string{"package.json", "go.mod", "frontend/package.json"},
			expected:  []string{"go", "npm"},
		},
		{
			name:      "no known manifest",
			filenames: []string{"README.md", "Makefile"},
			expected:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectEcosystems(tc.filenames)
			sort.Strings(got)
			sort.Strings(tc.expected)

			if len(got) != len(tc.expected) {
				t.Fatalf("expected length %d, got %d", len(tc.expected), len(got))
			}

			for i := range got {
				if got[i] != tc.expected[i] {
					t.Errorf("expected %v, got %v", tc.expected, got)
					break
				}
			}
		})
	}
}
