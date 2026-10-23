package normalize

import (
	"testing"
	"tijeri/internal/models"
)

func TestDetermineNVDStatus(t *testing.T) {
	if s := DetermineNVDStatus(true, false); s != "full" {
		t.Errorf("Expected full, got %s", s)
	}
	if s := DetermineNVDStatus(false, true); s != "lowest_priority" {
		t.Errorf("Expected lowest_priority, got %s", s)
	}
	if s := DetermineNVDStatus(false, false); s != "not_scheduled" {
		t.Errorf("Expected not_scheduled, got %s", s)
	}
}

func TestCheckNVDContradiction(t *testing.T) {
	t.Run("Valid full", func(t *testing.T) {
		f := models.Finding{
			NVDEnrichmentStatus: "full",
			CVSS: &models.CVSS{Score: 5.0, Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		}
		if err := CheckNVDContradiction(f); err != nil {
			t.Errorf("Unexpected error for valid full status: %v", err)
		}
	})

	t.Run("Valid not_scheduled", func(t *testing.T) {
		f := models.Finding{
			NVDEnrichmentStatus: "not_scheduled",
			CVSS: nil,
		}
		if err := CheckNVDContradiction(f); err != nil {
			t.Errorf("Unexpected error for valid not_scheduled status: %v", err)
		}
	})

	t.Run("Contradiction", func(t *testing.T) {
		f := models.Finding{
			NVDEnrichmentStatus: "full",
			CVSS: nil,
		}
		if err := CheckNVDContradiction(f); err == nil {
			t.Error("Expected error for contradiction (full status but nil CVSS)")
		}
	})
}
