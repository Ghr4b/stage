package govulncheck

import (
	"context"
	"encoding/json"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type GovulncheckVuln struct {
	OSV     string `json:"osv"`
	Module  string `json:"module"`
	Version string `json:"version"`
}

type Config struct {
	BinPath string // Override binary path (default: "govulncheck")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "govulncheck" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "go")
	}
	return false
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	workDir := asset.Metadata["path"]
	if workDir == "" {
		workDir = asset.CanonicalName
	}
	if workDir == "" {
		return models.FindingsBatch{}, nil
	}

	raw, err := adapters.RunCLIScanner(ctx, "govulncheck", []string{"-json", "./..."}, nil, workDir)
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var vulns []GovulncheckVuln
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, v := range vulns {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "govulncheck", VulnerabilityID: v.OSV,
			Component: v.Module, ComponentVersion: v.Version, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
