package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

// NucleiResult represents a single Nuclei JSONL result line.
type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatcherName string `json:"matcher-name"`
	Host        string `json:"host"`
	IP          string `json:"ip"`
	Port        string `json:"port"`
	CurledURL   string `json:"curl-command"`
	CVEID       string `json:"cve-id,omitempty"`
}

type Config struct {
	BinPath     string // Override binary path (default: "nuclei")
	TemplatesDir string // Optional custom templates directory
	RateLimit   int    // Requests per second (default: 150)
}

type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "nuclei" }

func (a *Adapter) Supports(asset models.Asset) bool {
	return asset.Type == "host"
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	target := asset.Metadata["host"]
	if target == "" {
		target = asset.CanonicalName
	}
	if target == "" {
		return models.FindingsBatch{}, nil
	}

	args := []string{
		"-target", target,
		"-jsonl",
		"-silent",
		"-duc",       // disable update check (works offline / no template re-download)
		"-nmhe",      // don't skip host on scan errors
		"-severity", "low,medium,high,critical",
		"-timeout", "10",
		"-retries", "2",
	}
	templatesDir := a.Config.TemplatesDir
	if templatesDir == "" {
		templatesDir = "/root/nuclei-templates"
	}
	args = append(args, "-t", templatesDir)
	if a.Config.RateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", a.Config.RateLimit))
	}

	raw, err := adapters.RunCLIScanner(ctx, "nuclei", args, nil, "")
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return ParseOutput(raw, asset.AssetID)
}

// ParseOutput parses raw Nuclei NDJSON output (one JSON object per line) into findings.
func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	now := time.Now()
	var findings []models.Finding

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r NucleiResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		vulnID := r.CVEID
		if vulnID == "" {
			vulnID = r.TemplateID
		}
		findings = append(findings, models.Finding{
			AssetID:         assetID,
			SourceTool:      "nuclei",
			VulnerabilityID: vulnID,
			Component:       r.TemplateID,
			Status:          "open",
			FirstSeen:       now,
			LastSeen:        now,
		})
	}

	return models.FindingsBatch{Findings: findings}, nil
}
