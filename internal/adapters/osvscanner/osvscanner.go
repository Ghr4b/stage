package osvscanner

import (
	"context"
	"encoding/json"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type OSVResult struct {
	ID      string `json:"id"`
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type OSVOutput struct {
	Results []OSVResult `json:"results"`
}

type Config struct {
	BinPath string // Override binary path (default: "osv-scanner")
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "osv-scanner" }

func (a *Adapter) Supports(asset models.Asset) bool {
	return asset.Type == "repo"
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	target := asset.Metadata["path"]
	if target == "" {
		target = asset.CanonicalName
	}
	if target == "" {
		return models.FindingsBatch{}, nil
	}

	raw, err := adapters.RunCLIScanner(ctx, "osv-scanner", []string{"--format", "json", target}, nil, "")
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var output OSVOutput
	if err := json.Unmarshal(raw, &output); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, r := range output.Results {
		findings = append(findings, models.Finding{
			AssetID: assetID, SourceTool: "osv-scanner", VulnerabilityID: r.ID,
			Component: r.Package.Name, ComponentVersion: r.Package.Version, Status: "open",
			FirstSeen: now, LastSeen: now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
