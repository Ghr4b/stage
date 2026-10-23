package prowler

import (
	"context"
	"testing"

	"tijeri/internal/models"
)

func TestAdapter_Name(t *testing.T) {
	adapter := NewAdapter()
	if adapter.Name() != "prowler" {
		t.Errorf("Expected 'prowler', got '%s'", adapter.Name())
	}
}

func TestAdapter_Supports(t *testing.T) {
	adapter := NewAdapter()

	assetCloud := models.Asset{Type: "cloud"}
	if !adapter.Supports(assetCloud) {
		t.Errorf("Expected prowler to support 'cloud' asset type")
	}

	assetHost := models.Asset{Type: "host"}
	if adapter.Supports(assetHost) {
		t.Errorf("Expected prowler not to support 'host' asset type")
	}
}

func TestAdapter_ParseOutput(t *testing.T) {
	adapter := NewAdapter()
	asset := models.Asset{AssetID: "asset-123", Type: "cloud"}

	output := []byte(`[
		{
			"Status": "FAIL",
			"Severity": "Critical",
			"CheckID": "iam_user_mfa_enabled",
			"ResourceName": "user1"
		},
		{
			"Status": "PASS",
			"Severity": "Low",
			"CheckID": "s3_bucket_public_access",
			"ResourceName": "bucket1"
		}
	]`)

	batch, err := adapter.ParseOutput(output, asset)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(batch.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(batch.Findings))
	}

	finding := batch.Findings[0]
	if finding.SourceTool != "prowler" {
		t.Errorf("Expected SourceTool 'prowler', got '%s'", finding.SourceTool)
	}
	if finding.VulnerabilityID != "iam_user_mfa_enabled" {
		t.Errorf("Expected VulnerabilityID 'iam_user_mfa_enabled', got '%s'", finding.VulnerabilityID)
	}
	if finding.AssetID != "asset-123" {
		t.Errorf("Expected AssetID 'asset-123', got '%s'", finding.AssetID)
	}
	if finding.Status != "open" {
		t.Errorf("Expected Status 'open', got '%s'", finding.Status)
	}
}

func TestAdapter_Scan(t *testing.T) {
	adapter := NewAdapter()
	asset := models.Asset{AssetID: "asset-123", Type: "cloud"}

	batch, err := adapter.Scan(context.Background(), asset)
	if err != nil {
		// Expected when prowler binary is not installed
		t.Skipf("prowler binary not available (expected in CI): %v", err)
	}
	if len(batch.Findings) != 0 {
		t.Errorf("Expected 0 findings from scan with no cloud creds, got %d", len(batch.Findings))
	}
}
