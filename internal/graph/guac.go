package graph

import (
	"context"
	"fmt"
)

type GUACClient interface {
	IngestSBOM(ctx context.Context, sbomJSON []byte) error
	QueryBlastRadius(ctx context.Context, cveID string) ([]string, error)
}

type MockGUACClient struct {
	nodes map[string][]string
}

func NewMockGUACClient() *MockGUACClient {
	return &MockGUACClient{
		nodes: make(map[string][]string),
	}
}

func (m *MockGUACClient) IngestSBOM(ctx context.Context, sbomJSON []byte) error {
	// Parse a fake SBOM format to build the graph
	// Format: source -> artifact -> vulnerability
	// We'll simulate by checking a known fixture byte
	if string(sbomJSON) == "fixture-1" {
		m.nodes["CVE-2023-1111"] = append(m.nodes["CVE-2023-1111"], "artifact-1")
		m.nodes["artifact-1"] = append(m.nodes["artifact-1"], "source-repo-1")
	} else if string(sbomJSON) == "fixture-2" {
		m.nodes["CVE-2024-2222"] = append(m.nodes["CVE-2024-2222"], "artifact-2")
		m.nodes["artifact-2"] = append(m.nodes["artifact-2"], "source-repo-2")
	}
	return nil
}

func (m *MockGUACClient) QueryBlastRadius(ctx context.Context, cveID string) ([]string, error) {
	artifacts, ok := m.nodes[cveID]
	if !ok {
		return nil, fmt.Errorf("cve not found")
	}
	
	var sources []string
	for _, a := range artifacts {
		srcs := m.nodes[a]
		sources = append(sources, srcs...)
	}
	
	return sources, nil
}
