package secrets

import (
	"context"
	"testing"
	"tijeri/internal/models"
)

// --- Mock implementations ---

type MockVerifierLive struct{}

func (m *MockVerifierLive) VerifyLive(ctx context.Context, secretType, secretValue string) (bool, error) {
	return true, nil
}

type MockVerifierDead struct{}

func (m *MockVerifierDead) VerifyLive(ctx context.Context, secretType, secretValue string) (bool, error) {
	return false, nil
}

type MockCorrelator struct{}

func (m *MockCorrelator) Correlate(ctx context.Context, secretType, secretValue string) ([]AffectedAsset, error) {
	return []AffectedAsset{
		{AssetID: "infra-aws-ec2-i-12345", AssetType: "cloud_infra"},
	}, nil
}

// --- P10-1: Named negative test (I11) ---

func TestUnverifiedSecretDoesNotEscalate(t *testing.T) {
	f := models.Finding{
		FindingID:       "gitleaks-001",
		AssetID:         "repo-my-app",
		SourceTool:      "gitleaks",
		VulnerabilityID: "gitleaks-rule-aws-key",
		Component:       "aws_access_key",
		Status:          "open",
	}

	sf := ProcessDetection(f)

	// (a) No Critical severity set
	if sf.Finding.Status == "critical" {
		t.Fatal("I11 violated: raw Gitleaks detection must NEVER set Critical severity")
	}
	// The CVSS on the finding should not be critical-range
	if sf.Finding.CVSS != nil && sf.Finding.CVSS.Score >= 9.0 {
		t.Fatal("I11 violated: raw detection CVSS must not be in critical range")
	}

	// (b) No blast-radius query executed as a side effect
	if sf.BlastRadiusRun {
		t.Fatal("I11 violated: blast-radius query must NOT run on an unverified detection")
	}

	// Verify it's not marked as verified
	if sf.Verified {
		t.Fatal("Detection stage should not mark secret as verified")
	}
}

// --- P10-2: Verification stage ---

func TestVerifiedLiveSecretProceedsToCorrelation(t *testing.T) {
	f := models.Finding{
		FindingID:  "gitleaks-002",
		AssetID:    "repo-my-app",
		SourceTool: "gitleaks",
		Component:  "aws_access_key",
		Status:     "open",
	}

	sf := ProcessDetection(f)
	ctx := context.Background()

	err := ProcessVerification(ctx, &sf, &MockVerifierLive{}, "AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !sf.Verified {
		t.Fatal("Expected secret to be marked verified-live")
	}
}

func TestDeadSecretDoesNotEscalate(t *testing.T) {
	f := models.Finding{
		FindingID:  "gitleaks-003",
		AssetID:    "repo-my-app",
		SourceTool: "gitleaks",
		Component:  "aws_access_key",
		Status:     "open",
	}

	sf := ProcessDetection(f)
	ctx := context.Background()

	err := ProcessVerification(ctx, &sf, &MockVerifierDead{}, "AKIAIOSFODNN7ROTATED")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if sf.Verified {
		t.Fatal("Dead/rotated credential should NOT be marked verified")
	}

	// Attempting blast-radius on a dead secret should fail
	_, err = ProcessBlastRadius(ctx, &sf, &MockCorrelator{}, "AKIAIOSFODNN7ROTATED")
	if err == nil {
		t.Fatal("Expected error when attempting blast-radius on unverified secret")
	}

	if sf.BlastRadiusRun {
		t.Fatal("Blast-radius should NOT have run on a dead/rotated credential")
	}
}

// --- P10-3: Blast-radius correlation ---

func TestBlastRadiusCorrelationOnVerifiedSecret(t *testing.T) {
	f := models.Finding{
		FindingID:  "gitleaks-004",
		AssetID:    "repo-my-app",
		SourceTool: "gitleaks",
		Component:  "aws_access_key",
		Status:     "open",
	}

	sf := ProcessDetection(f)
	ctx := context.Background()

	ProcessVerification(ctx, &sf, &MockVerifierLive{}, "AKIAIOSFODNN7LIVE")

	escalated, err := ProcessBlastRadius(ctx, &sf, &MockCorrelator{}, "AKIAIOSFODNN7LIVE")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !sf.BlastRadiusRun {
		t.Fatal("Expected blast-radius to have been executed")
	}

	// Should escalate BOTH the repo asset AND the target infra
	if len(escalated) < 2 {
		t.Fatalf("Expected at least 2 escalated assets (repo + infra), got %d", len(escalated))
	}

	foundRepo := false
	foundInfra := false
	for _, e := range escalated {
		if e.AssetID == "repo-my-app" && e.Severity == "critical" {
			foundRepo = true
		}
		if e.AssetID == "infra-aws-ec2-i-12345" && e.Severity == "critical" {
			foundInfra = true
		}
	}

	if !foundRepo {
		t.Error("Expected source repo asset to be escalated to Critical")
	}
	if !foundInfra {
		t.Error("Expected target infra asset to be escalated to Critical")
	}
}
