package resolver

import (
	"testing"
	"time"
)

func TestInventoryLatestWinsPerPackage(t *testing.T) {
	state := NewInventoryState()
	now := time.Now()

	// Source A reports earlier
	reportA := InventoryReport{
		Source:    "wazuh",
		Timestamp: now.Add(-2 * time.Hour),
		Packages: []SoftwarePackage{
			{Name: "openssl", Version: "1.1.1"},
			{Name: "curl", Version: "7.68.0"},
		},
	}

	// Source B reports later
	reportB := InventoryReport{
		Source:    "container-scan",
		Timestamp: now.Add(-1 * time.Hour),
		Packages: []SoftwarePackage{
			{Name: "openssl", Version: "3.0.2"}, // Newer timestamp, different version
			{Name: "wget", Version: "1.21.2"},   // New package
		},
	}

	state.MergeReport(reportA)
	state.MergeReport(reportB)

	// Check openssl - should be 3.0.2 from container-scan
	ver, src, ts, ok := state.GetRecord("openssl")
	if !ok {
		t.Fatal("openssl package missing")
	}
	if ver != "3.0.2" {
		t.Errorf("Expected openssl version 3.0.2, got %s", ver)
	}
	if src != "container-scan" {
		t.Errorf("Expected source container-scan, got %s", src)
	}
	if ts != reportB.Timestamp {
		t.Errorf("Expected timestamp %v, got %v", reportB.Timestamp, ts)
	}

	// Check curl - should be from wazuh (only reporter)
	ver, src, _, ok = state.GetRecord("curl")
	if !ok || ver != "7.68.0" || src != "wazuh" {
		t.Errorf("curl record incorrect: %s from %s", ver, src)
	}

	// Check wget - should be from container-scan (only reporter)
	ver, src, _, ok = state.GetRecord("wget")
	if !ok || ver != "1.21.2" || src != "container-scan" {
		t.Errorf("wget record incorrect: %s from %s", ver, src)
	}

	// Out-of-order delivery: Source C reports an OLDER timestamp for curl
	reportC := InventoryReport{
		Source:    "legacy-scanner",
		Timestamp: now.Add(-24 * time.Hour), // Older than wazuh!
		Packages: []SoftwarePackage{
			{Name: "curl", Version: "7.0.0"},
		},
	}
	state.MergeReport(reportC)

	// curl should still be 7.68.0 from wazuh
	ver, src, _, ok = state.GetRecord("curl")
	if !ok || ver != "7.68.0" || src != "wazuh" {
		t.Errorf("curl was incorrectly overwritten by an older report! Got %s from %s", ver, src)
	}
}
