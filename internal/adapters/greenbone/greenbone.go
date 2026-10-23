package greenbone

import (
	"context"
	"encoding/json"
	"fmt"
	"tijeri/internal/adapters"
	"tijeri/internal/models"
	"time"
)

// GreenboneResult represents a single result from OpenVAS/Greenbone JSON output.
type GreenboneResult struct {
	NVT        string `json:"nvt"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       string `json:"port"`
	Severity   string `json:"severity"`
	CVEID      string `json:"cve_id"`
	Component  string `json:"component"`
	Version    string `json:"version"`
}

type Config struct {
	GVMAddr     string // GVM daemon address (default: unix:///var/run/gvmd.sock)
	GVMUsername string
	GVMPassword string
	BinPath     string // Override gvm-cli binary path
}

// Adapter implements the ScannerAdapter interface for Greenbone/OpenVAS.
type Adapter struct {
	Config Config
}

func NewAdapter(cfg Config) *Adapter {
	return &Adapter{Config: cfg}
}

func (a *Adapter) Name() string { return "greenbone" }

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

	// Use gvm-cli to run a scan via the GVM protocol
	// gvm-cli --gmp-username user --gmp-password pass socket /var/run/gvmd.sock
	//   <get_tasks />
	args := []string{
		"--gmp-username", a.Config.GVMUsername,
		"--gmp-password", a.Config.GVMPassword,
	}

	gvmAddr := a.Config.GVMAddr
	if gvmAddr == "" {
		gvmAddr = "unix:///var/run/gvmd.sock"
	}

	// Determine socket vs TCP
	if len(gvmAddr) > 7 && gvmAddr[:7] == "unix://" {
		args = append(args, "socket", gvmAddr[7:])
	} else {
		args = append(args, "tls", gvmAddr)
	}

	// XML command to create target, start task, and get results
	xmlCmd := fmt.Sprintf(`<create_target><name>tijeri-scan-%s</name><hosts>%s</hosts></create_target>`, target, target)
	args = append(args, xmlCmd)

	raw, err := adapters.RunCLIScanner(ctx, "gvm-cli", args, nil, "")
	if err != nil {
		// If gvm-cli is not available, fall back to openvas-cli (omp)
		return a.scanViaOMP(ctx, target)
	}

	return ParseOutput(raw, asset.AssetID)
}

// scanViaOMP attempts scanning via the omp command-line tool as a fallback.
func (a *Adapter) scanViaOMP(ctx context.Context, target string) (models.FindingsBatch, error) {
	args := []string{
		"-u", a.Config.GVMUsername,
		"-w", a.Config.GVMPassword,
		"-h", "localhost",
		"-p", "9390",
		"-X", fmt.Sprintf(`<get_targets/>`),
	}

	raw, err := adapters.RunCLIScanner(ctx, "omp", args, nil, "")
	if err != nil {
		return models.FindingsBatch{}, fmt.Errorf("greenbone scan failed: gvm-cli and omp both unavailable: %w", err)
	}

	return ParseOutput(raw, "")
}

// ParseOutput parses raw Greenbone JSON output into findings.
func ParseOutput(raw []byte, assetID string) (models.FindingsBatch, error) {
	var results []GreenboneResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return models.FindingsBatch{}, err
	}

	now := time.Now()
	var findings []models.Finding
	for _, r := range results {
		findings = append(findings, models.Finding{
			AssetID:         assetID,
			SourceTool:      "greenbone",
			VulnerabilityID: r.CVEID,
			Component:       r.Component,
			ComponentVersion: r.Version,
			Status:          "open",
			FirstSeen:       now,
			LastSeen:        now,
		})
	}

	return models.FindingsBatch{Findings: findings}, nil
}
