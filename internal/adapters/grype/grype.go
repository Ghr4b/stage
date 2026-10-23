package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"tijeri/internal/models"
	"time"
)

// Config holds configuration for the Grype adapter.
type Config struct {
	VEXEnabled bool
}

type GrypeMatch struct {
	Vulnerability struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"vulnerability"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

type GrypeOutput struct {
	Matches []GrypeMatch `json:"matches"`
}

// Adapter implements the ScannerAdapter interface for Grype.
type Adapter struct {
	Config Config
}

func (a *Adapter) Name() string { return "grype" }

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
	binPath, err := exec.LookPath("grype")
	if err != nil {
		return models.FindingsBatch{}, fmt.Errorf("grype not found in PATH: %w", err)
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
			return models.FindingsBatch{}, fmt.Errorf("grype scan failed (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return models.FindingsBatch{}, fmt.Errorf("grype scan failed: %w", err)
	}

	return ParseOutput(output, asset.AssetID)
}

// ParseOutput parses raw Grype JSON output into findings.
func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output GrypeOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}

	now := time.Now()
	var findings []models.Finding
	for _, m := range output.Matches {
		findings = append(findings, models.Finding{
			AssetID:          assetID,
			SourceTool:       "grype",
			VulnerabilityID:  m.Vulnerability.ID,
			Component:        m.Artifact.Name,
			ComponentVersion: m.Artifact.Version,
			Status:           "open",
			FirstSeen:        now,
			LastSeen:         now,
		})
	}

	return models.FindingsBatch{Findings: findings}, nil
}
