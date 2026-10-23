package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

// Config holds configuration for the Trivy adapter.
type Config struct {
	VEXEnabled bool              // Enables --vex flag passthrough
	VEXPath    string            // Path to VEX document
	Env        map[string]string // Extra env vars (e.g., registry credentials)
	Severity   string            // Filter: comma-separated severities (default: all)
}

// TrivyResult represents a single vulnerability from Trivy JSON output.
type TrivyResult struct {
	Target          string              `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
	FixedVersion     string `json:"FixedVersion"`
}

// Adapter implements the ScannerAdapter interface for Trivy.
type Adapter struct {
	Config Config
}

func (a *Adapter) Name() string { return "trivy" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if asset.Type == "container" {
		return true
	}
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return containsDocker(ecosystems)
	}
	return false
}

func containsDocker(s string) bool {
	for _, part := range splitComma(s) {
		if part == "docker" {
			return true
		}
	}
	return false
}

func splitComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	result = append(result, trimSpace(s[start:]))
	return result
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	target := asset.Metadata["image"]
	if target == "" {
		target = asset.CanonicalName
	}
	if target == "" {
		return models.FindingsBatch{}, nil
	}

	args := []string{"image", "--format", "json", "--quiet"}
	if a.Config.VEXEnabled && a.Config.VEXPath != "" {
		args = append(args, "--vex", a.Config.VEXPath)
	}
	if a.Config.Severity != "" {
		args = append(args, "--severity", a.Config.Severity)
	}
	args = append(args, target)

	raw, err := adapters.RunCLIScanner(ctx, "trivy", args, a.Config.Env, "")
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

// ParseOutput parses raw Trivy JSON output into findings.
func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var results []TrivyResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return models.FindingsBatch{}, err
	}

	now := time.Now()
	var findings []models.Finding
	for _, r := range results {
		for _, v := range r.Vulnerabilities {
			finding := models.Finding{
				AssetID:          assetID,
				SourceTool:       "trivy",
				VulnerabilityID:  v.VulnerabilityID,
				Component:        v.PkgName,
				ComponentVersion: v.InstalledVersion,
				Status:           "open",
				FirstSeen:        now,
				LastSeen:         now,
			}
			if v.FixedVersion != "" {
				finding.ComponentVersion = fmt.Sprintf("%s (fixed: %s)", v.InstalledVersion, v.FixedVersion)
			}
			findings = append(findings, finding)
		}
	}

	return models.FindingsBatch{Findings: findings}, nil
}
