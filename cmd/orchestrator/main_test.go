package main

import (
	"context"
	"strings"
	"testing"

	"tijeri/internal/adapters"
	"tijeri/internal/models"
)

type capabilityTestScanner struct{}

func (capabilityTestScanner) Supports(models.Asset) bool { return true }
func (capabilityTestScanner) Scan(context.Context, models.Asset) (models.FindingsBatch, error) {
	return models.FindingsBatch{}, nil
}
func (capabilityTestScanner) Name() string { return "trivy" }

func TestRegisteredAdaptersHaveExecutableRequirements(t *testing.T) {
	t.Setenv("GVM_SOCKET", "")
	_, scannerMap := initAdapters()
	names := make([]string, 0, len(scannerMap))
	for name := range scannerMap {
		names = append(names, name)
	}
	for _, capability := range adapters.InspectScannerCapabilities(names) {
		for _, missing := range capability.Missing {
			if missing == "dependency mapping" {
				t.Errorf("registered scanner %q has no executable requirement", capability.Scanner)
			}
		}
	}
}

func TestScannerPreflightFailsWhenRequiredExecutableIsMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SCANNER_PREFLIGHT_REQUIRED", "true")

	err := validateScannerRuntime(map[string]Scanner{"trivy": capabilityTestScanner{}})
	if err == nil || !strings.Contains(err.Error(), "trivy") {
		t.Fatalf("validateScannerRuntime() error = %v, want missing trivy dependency", err)
	}
}

func TestScannerPreflightAllowsMissingExecutableWhenNotRequired(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SCANNER_PREFLIGHT_REQUIRED", "false")

	if err := validateScannerRuntime(map[string]Scanner{"trivy": capabilityTestScanner{}}); err != nil {
		t.Fatalf("validateScannerRuntime() error = %v, want nil", err)
	}
}
