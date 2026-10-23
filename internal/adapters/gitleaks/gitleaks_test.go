package gitleaks

import (
	"strings"
	"testing"
	"tijeri/internal/models"
)

const fixtureJSON = `[
	{
		"Description": "AWS Access Key",
		"Match": "AKIAIOSFODNN7EXAMPLE",
		"Secret": "AKIAIOSFODNN7EXAMPLE",
		"File": "config.yml",
		"RuleID": "aws-access-key"
	},
	{
		"Description": "Generic API Key",
		"Match": "api_key = '1234567890'",
		"Secret": "1234567890",
		"File": "main.py",
		"RuleID": "generic-api-key"
	}
]`

func TestGitleaksSupports(t *testing.T) {
	a := &Adapter{}
	if !a.Supports(models.Asset{Type: "repo"}) {
		t.Error("should support repo")
	}
	if a.Supports(models.Asset{Type: "host"}) {
		t.Error("should not support host")
	}
}

func TestGitleaksName(t *testing.T) {
	if (&Adapter{}).Name() != "gitleaks" {
		t.Error("wrong name")
	}
}

func TestGitleaksParse(t *testing.T) {
	b, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Findings) != 2 {
		t.Fatalf("expected 2, got %d", len(b.Findings))
	}
	if b.Findings[0].VulnerabilityID != "aws-access-key" {
		t.Error("wrong vuln id")
	}
	if b.Findings[0].SourceTool != "gitleaks" {
		t.Error("wrong source tool")
	}
}

// TestGitleaksOutputNeverSetsCriticalSeverity enforces Invariant I11
func TestGitleaksOutputNeverSetsCriticalSeverity(t *testing.T) {
	batch, err := ParseOutput([]byte(fixtureJSON), "a1")
	if err != nil {
		t.Fatal(err)
	}
	
	for _, f := range batch.Findings {
		if strings.ToLower(f.Status) == "critical" {
			t.Errorf("Invariant I11 violated: gitleaks finding %s has critical status", f.VulnerabilityID)
		}
	}
}
