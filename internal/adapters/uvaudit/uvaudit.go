package uvaudit

import (
	"context"
	"encoding/json"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type UVVuln struct {
	ID      string `json:"id"`
	Package string `json:"package"`
	Version string `json:"installed_version"`
}

type Config struct {
	BinPath string // Override binary path (default: "uv")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "uv audit" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "python")
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

	raw, err := adapters.RunCLIScanner(ctx, "uv", []string{"audit", "--output-format", "json"}, nil, workDir)
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var vulns []UVVuln
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, v := range vulns {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "uv audit", VulnerabilityID: v.ID,
			Component: v.Package, ComponentVersion: v.Version, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
