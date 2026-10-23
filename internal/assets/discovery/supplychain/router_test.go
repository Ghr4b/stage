package supplychain

import (
	"testing"
	"tijeri/internal/assets/discovery/repo"
)

func TestRouterIntegrationWithEcosystemLogic(t *testing.T) {
	// Integration requirement: Flags match the ecosystem-detection logic from P1-1 exactly
	
	// Simulated file list that P1-1 webhook handler would process
	files := []string{"src/pyproject.toml", "deploy/Dockerfile", "README.md"}
	ecosystems := repo.DetectEcosystems(files) // P1-1 exact logic

	signal := repo.RepoSignalEvent{
		Type:       "github_repo",
		URL:        "https://github.com/test/test",
		Ecosystems: ecosystems, // Handed off to P1-7 plumbing
	}

	router := &Router{}
	flags := router.RouteRepoSignal(signal)

	// Unit requirement: a repo signal with a Dockerfile present is flagged for container-scan routing
	if !flags.ContainerScan {
		t.Errorf("Expected ContainerScan flag to be true due to Dockerfile")
	}

	// Unit requirement: a pyproject.toml repo is flagged for SCA routing
	if !flags.SCA {
		t.Errorf("Expected SCA flag to be true due to pyproject.toml")
	}
}
