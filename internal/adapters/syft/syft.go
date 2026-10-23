package syft

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"tijeri/internal/models"
	"time"
)

// SyftPackage represents a package from Syft SBOM output.
type SyftPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl"`
}

type SyftOutput struct {
	Artifacts []SyftPackage `json:"artifacts"`
}

// Adapter implements the ScannerAdapter interface for Syft (SBOM generation).
type Adapter struct{}

func (a *Adapter) Name() string { return "syft" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if asset.Type == "container" {
		return true
	}
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "docker")
	}
	return false
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	binPath, err := exec.LookPath("syft")
	if err != nil {
		return models.FindingsBatch{}, fmt.Errorf("syft not found in PATH: %w", err)
	}

	target := asset.Metadata["image"]
	if target == "" {
		target = asset.CanonicalName
	}

	cmd := exec.CommandContext(ctx, binPath, target, "-o", "json")
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && len(output) > 0 {
			return ParseOutput(output, asset.AssetID)
		} else if exitErr != nil {
			return models.FindingsBatch{}, fmt.Errorf("syft scan failed (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return models.FindingsBatch{}, fmt.Errorf("syft scan failed: %w", err)
	}

	return ParseOutput(output, asset.AssetID)
}

// ParseOutput parses Syft JSON SBOM into an inventory-style FindingsBatch.
// Note: Syft produces SBOMs not vulnerabilities. Findings here represent
// inventory items that downstream scanners will correlate.
func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output SyftOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}

	now := time.Now()
	var findings []models.Finding
	for _, pkg := range output.Artifacts {
		findings = append(findings, models.Finding{
			AssetID:          assetID,
			SourceTool:       "syft",
			Component:        pkg.Name,
			ComponentVersion: pkg.Version,
			Status:           "open",
			FirstSeen:        now,
			LastSeen:         now,
		})
	}

	return models.FindingsBatch{Findings: findings}, nil
}
