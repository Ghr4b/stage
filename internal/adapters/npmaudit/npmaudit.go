package npmaudit

import (
	"context"
	"encoding/json"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type NPMAdvisory struct {
	ID       int    `json:"id"`
	Name     string `json:"module_name"`
	Version  string `json:"findings_version"`
	Severity string `json:"severity"`
	CVEID    string `json:"cves"`
}

type NPMAuditOutput struct {
	Advisories map[string]NPMAdvisory `json:"advisories"`
}

type Config struct {
	BinPath string // Override binary path (default: "npm")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "npm audit" }

func (a *Adapter) Supports(asset models.Asset) bool {
	if ecosystems, ok := asset.Metadata["ecosystems"]; ok {
		return strings.Contains(ecosystems, "node")
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

	raw, err := adapters.RunCLIScanner(ctx, "npm", []string{"audit", "--json"}, nil, workDir)
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output NPMAuditOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, adv := range output.Advisories {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "npm audit", VulnerabilityID: adv.CVEID,
			Component: adv.Name, ComponentVersion: adv.Version, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
