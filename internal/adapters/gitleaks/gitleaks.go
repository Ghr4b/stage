package gitleaks

import (
	"context"
	"encoding/json"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

type GitleaksResult struct {
	Description string `json:"Description"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	RuleID      string `json:"RuleID"`
}

type Config struct {
	BinPath   string // Override binary path (default: "gitleaks")
	RulesPath string // Optional custom rules file
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "gitleaks" }

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

	args := []string{"detect", "--source=" + target, "--report-format=json", "--no-banner"}
	if a.Config.RulesPath != "" {
		args = append(args, "--config="+a.Config.RulesPath)
	}

	raw, err := adapters.RunCLIScanner(ctx, "gitleaks", args, nil, "")
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var results []GitleaksResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return models.FindingsBatch{}, err
	}
	now := time.Now()
	var findings []models.Finding
	for _, r := range results {
		// I11: Gitleaks output must NEVER set a Critical severity.
		// We set Status to open to reflect base pattern matching without escalation.
		findings = append(findings, models.Finding{
			AssetID:         assetID,
			SourceTool:      "gitleaks",
			VulnerabilityID: r.RuleID,
			Component:       r.File,
			Status:          "open",
			FirstSeen:       now,
			LastSeen:        now,
		})
	}
	return models.FindingsBatch{Findings: findings}, nil
}
