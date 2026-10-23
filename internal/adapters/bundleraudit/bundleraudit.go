package bundleraudit

import (
	"context"
	"encoding/json"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type BundlerVuln struct {
	Advisory string `json:"advisory"`
	Gem      string `json:"gem"`
	Version  string `json:"version"`
}

type Config struct {
	BinPath string // Override binary path (default: "bundle-audit")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "bundler-audit" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "ruby")
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

	raw, err := adapters.RunCLIScanner(ctx, "bundle-audit", []string{"exec", "--format", "json"}, nil, workDir)
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var vulns []BundlerVuln
	if err := json.Unmarshal(raw, &vulns); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, v := range vulns {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "bundler-audit", VulnerabilityID: v.Advisory,
			Component: v.Gem, ComponentVersion: v.Version, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
