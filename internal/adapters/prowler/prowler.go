package prowler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"tijeri/internal/adapters"
	"tijeri/internal/models"
)

type Adapter struct{}

func NewAdapter() *Adapter {
	return &Adapter{}
}

func (a *Adapter) Name() string {
	return "prowler"
}

func (a *Adapter) Supports(asset models.Asset) bool {
	return asset.Type == "cloud"
}

type ProwlerFinding struct {
	Status   string `json:"Status"`
	Severity string `json:"Severity"`
	CheckID  string `json:"CheckID"`
	Resource string `json:"ResourceName"`
}

func (a *Adapter) ParseOutput(output []byte, asset models.Asset) (models.FindingsBatch, error) {
	var prowlerFindings []ProwlerFinding
	if err := json.Unmarshal(output, &prowlerFindings); err != nil {
		return models.FindingsBatch{}, fmt.Errorf("failed to parse prowler output: %w", err)
	}

	var batch models.FindingsBatch
	for _, pf := range prowlerFindings {
		if pf.Status != "FAIL" {
			continue
		}

		finding := models.Finding{
			FindingID:       fmt.Sprintf("%s-%s", pf.CheckID, pf.Resource),
			AssetID:         asset.AssetID,
			SourceTool:      a.Name(),
			VulnerabilityID: pf.CheckID,
			Component:       pf.Resource,
			Status:          "open",
			FirstSeen:       time.Now().UTC(),
			LastSeen:        time.Now().UTC(),
		}
		batch.Findings = append(batch.Findings, finding)
	}

	return batch, nil
}

func (a *Adapter) Scan(ctx context.Context, asset models.Asset) (models.FindingsBatch, error) {
	env := make(map[string]string)

	// Read cloud credentials from asset metadata or environment
	if v, ok := asset.Metadata["aws_access_key_id"]; ok {
		env["AWS_ACCESS_KEY_ID"] = v
	} else if v := os.Getenv("AWS_ACCESS_KEY_ID"); v != "" {
		env["AWS_ACCESS_KEY_ID"] = v
	}
	if v, ok := asset.Metadata["aws_secret_access_key"]; ok {
		env["AWS_SECRET_ACCESS_KEY"] = v
	} else if v := os.Getenv("AWS_SECRET_ACCESS_KEY"); v != "" {
		env["AWS_SECRET_ACCESS_KEY"] = v
	}
	if v, ok := asset.Metadata["aws_default_region"]; ok {
		env["AWS_DEFAULT_REGION"] = v
	} else if v := os.Getenv("AWS_DEFAULT_REGION"); v != "" {
		env["AWS_DEFAULT_REGION"] = v
	}

	args := []string{"aws", "--compliance", "cis_level2", "--output-format", "json", "--quiet"}

	// If a specific profile is set, use it
	if profile, ok := asset.Metadata["aws_profile"]; ok {
		args = append(args, "--profile", profile)
	}

	raw, err := adapters.RunCLIScanner(ctx, "prowler", args, env, "")
	if err != nil {
		return models.FindingsBatch{}, err
	}

	return a.ParseOutput(raw, asset)
}
