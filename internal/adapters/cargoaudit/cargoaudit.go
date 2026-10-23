package cargoaudit

import (
	"context"
	"encoding/json"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type CargoVuln struct {
	Advisory struct {
		ID      string `json:"id"`
		Package string `json:"package"`
	} `json:"advisory"`
	Versions struct {
		Patched []string `json:"patched"`
	} `json:"versions"`
	AffectedVersion string `json:"affected_version"`
}

type CargoAuditOutput struct {
	Vulnerabilities struct {
		Found []CargoVuln `json:"found"`
	} `json:"vulnerabilities"`
}

type Config struct {
	BinPath string // Override binary path (default: "cargo-audit")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "cargo audit" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "rust")
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

	raw, err := adapters.RunCLIScanner(ctx, "cargo-audit", []string{"audit", "-o", "json"}, nil, workDir)
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output CargoAuditOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, v := range output.Vulnerabilities.Found {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "cargo audit", VulnerabilityID: v.Advisory.ID,
			Component: v.Advisory.Package, ComponentVersion: v.AffectedVersion, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
