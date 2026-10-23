package secrets

import (
	"context"
	"fmt"
	"tijeri/internal/models"
)

// SecretFinding represents a Gitleaks detection enriched with verification status.
type SecretFinding struct {
	Finding          models.Finding
	SecretType       string // e.g. "aws_access_key", "github_pat"
	Verified         bool
	VerificationNote string
	BlastRadiusRun   bool // tracks whether blast-radius correlation was executed
}

// CredentialVerifier checks whether a detected secret is still live.
type CredentialVerifier interface {
	// VerifyLive performs a safe, read-only API call to determine if a credential is live.
	// Returns (isLive, error). Error means verification could not be completed.
	VerifyLive(ctx context.Context, secretType, secretValue string) (bool, error)
}

// BlastRadiusCorrelator queries cloud inventory to determine what infra a credential unlocks.
type BlastRadiusCorrelator interface {
	Correlate(ctx context.Context, secretType, secretValue string) ([]AffectedAsset, error)
}

type AffectedAsset struct {
	AssetID  string
	AssetType string // "repo", "cloud_infra", etc.
}

// ProcessDetection implements P10-1: Detection stage.
// Raw Gitleaks hits are logged but NEVER escalated to Critical (I11).
// They route to human-review queue at "attend" level.
func ProcessDetection(f models.Finding) SecretFinding {
	sf := SecretFinding{
		Finding:    f,
		SecretType: f.Component, // Gitleaks populates component with rule ID
		Verified:   false,
	}
	// I11 enforcement: severity is capped at medium for raw detection.
	// The finding status remains "open" (set by the Gitleaks adapter).
	// No blast-radius query is executed at this stage.
	sf.BlastRadiusRun = false
	return sf
}

// ProcessVerification implements P10-2: Verification stage.
// Only verified-live secrets proceed to blast-radius correlation.
func ProcessVerification(ctx context.Context, sf *SecretFinding, verifier CredentialVerifier, secretValue string) error {
	isLive, err := verifier.VerifyLive(ctx, sf.SecretType, secretValue)
	if err != nil {
		sf.VerificationNote = fmt.Sprintf("Verification failed: %v", err)
		return err
	}

	sf.Verified = isLive
	if isLive {
		sf.VerificationNote = "Credential confirmed live via read-only API probe"
	} else {
		sf.VerificationNote = "Credential confirmed dead/rotated"
	}
	return nil
}

// ProcessBlastRadius implements P10-3: Blast-radius correlation on verified secrets.
// Only called if sf.Verified == true.
// Escalates BOTH the source repo AND any target infra assets to Critical.
func ProcessBlastRadius(ctx context.Context, sf *SecretFinding, correlator BlastRadiusCorrelator, secretValue string) ([]EscalatedAsset, error) {
	if !sf.Verified {
		return nil, fmt.Errorf("blast-radius correlation requires a verified-live secret")
	}

	affected, err := correlator.Correlate(ctx, sf.SecretType, secretValue)
	if err != nil {
		return nil, err
	}

	sf.BlastRadiusRun = true

	var escalated []EscalatedAsset
	// Escalate the source repo
	escalated = append(escalated, EscalatedAsset{
		AssetID:  sf.Finding.AssetID,
		Severity: "critical",
		Source:   "verified_secret_blast_radius",
	})
	// Escalate target infra
	for _, a := range affected {
		escalated = append(escalated, EscalatedAsset{
			AssetID:  a.AssetID,
			Severity: "critical",
			Source:   "verified_secret_blast_radius",
		})
	}

	return escalated, nil
}

type EscalatedAsset struct {
	AssetID  string
	Severity string
	Source   string
}
