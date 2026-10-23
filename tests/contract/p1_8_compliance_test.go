package contract

import (
	"testing"

	"tijeri/internal/assets"
	"tijeri/internal/assets/discovery/container"
	"tijeri/internal/assets/discovery/directory"
	"tijeri/internal/assets/discovery/endpoint/wazuh"
	"tijeri/internal/assets/discovery/host"
	"tijeri/internal/assets/discovery/repo"
)

// identitySignalContractSuite runs the full IdentitySignal contract against any implementation.
// Every producer MUST pass these checks — zero exceptions (P1-8 requirement).
func identitySignalContractSuite(t *testing.T, name string, sig assets.IdentitySignal) {
	t.Helper()
	t.Run(name+"/SignalType_non_empty", func(t *testing.T) {
		if sig.SignalType() == "" {
			t.Error("SignalType() returned empty string")
		}
	})
	t.Run(name+"/Value_non_empty", func(t *testing.T) {
		if sig.Value() == "" {
			t.Error("Value() returned empty string")
		}
	})
	t.Run(name+"/Confidence_in_range", func(t *testing.T) {
		c := sig.Confidence()
		if c < 0.0 || c > 1.0 {
			t.Errorf("Confidence() = %f, want [0.0, 1.0]", c)
		}
	})
}

// TestP1_8_AllProducersPassContract runs the contract suite against every
// concrete IdentitySignal implementation built in P1-1 through P1-7.
func TestP1_8_AllProducersPassContract(t *testing.T) {

	// P1-1: RepoSignalEvent
	identitySignalContractSuite(t, "P1-1/RepoSignalEvent", &repo.RepoSignalEvent{
		Type:            "github_repo",
		URL:             "https://github.com/org/repo",
		ConfidenceScore: 1.0,
		Ecosystems:      []string{"go"},
	})

	// P1-3: HostSignalEvent (active)
	identitySignalContractSuite(t, "P1-3/HostSignalEvent/active", &host.HostSignalEvent{
		Type:            "ip",
		HostValue:       "10.0.0.1",
		ConfidenceScore: 0.9,
		Source:          "active",
	})

	// P1-3: HostSignalEvent (passive)
	identitySignalContractSuite(t, "P1-3/HostSignalEvent/passive", &host.HostSignalEvent{
		Type:            "ip",
		HostValue:       "10.0.0.2",
		ConfidenceScore: 1.0,
		Source:          "passive",
	})

	// P1-3: HostSignalEvent (agent)
	identitySignalContractSuite(t, "P1-3/HostSignalEvent/agent", &host.HostSignalEvent{
		Type:            "agent_uuid",
		HostValue:       "fleet-uuid-001",
		ConfidenceScore: 1.0,
		Source:          "agent",
	})

	// P1-4: ContainerSignalEvent (registry)
	identitySignalContractSuite(t, "P1-4/ContainerSignalEvent/registry", &container.ContainerSignalEvent{
		ImageDigest:     "sha256:abc123",
		ImageTags:       []string{"latest"},
		ConfidenceScore: 1.0,
		Source:          "registry",
	})

	// P1-4: ContainerSignalEvent (runtime)
	identitySignalContractSuite(t, "P1-4/ContainerSignalEvent/runtime", &container.ContainerSignalEvent{
		ImageDigest:     "sha256:def456",
		ConfidenceScore: 1.0,
		Source:          "runtime",
	})

	// P1-5: WazuhSignalEvent
	identitySignalContractSuite(t, "P1-5/WazuhSignalEvent", &wazuh.WazuhSignalEvent{
		AgentID:         "001",
		AgentName:       "web-server-01",
		AgentIP:         "10.0.0.50",
		MACAddress:      "00:1A:2B:3C:4D:5E",
		OSName:          "Ubuntu 22.04",
		ConfidenceScore: 1.0,
		Source:          "wazuh",
	})

	// P1-6: DirectorySignalEvent
	identitySignalContractSuite(t, "P1-6/DirectorySignalEvent", &directory.DirectorySignalEvent{
		ObjectSID:       "S-1-5-21-3623811015-3361044348-30300820-1013",
		Hostname:        "server01.corp.local",
		ConfidenceScore: 1.0,
		Source:          "active_directory",
	})
}
