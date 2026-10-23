package secrets

import (
	"testing"
)

func TestSupplyChainProvenance(t *testing.T) {
	signed := Provenance{
		DigestID:         "sha256:aaa",
		CosignSigned:     true,
		SLSAAttested:     true,
		AttestationLevel: "slsa_level_3",
	}

	unsigned := Provenance{
		DigestID:         "sha256:bbb",
		CosignSigned:     false,
		SLSAAttested:     false,
		AttestationLevel: "none",
	}

	r1 := GenerateProvenanceReport(signed)
	r2 := GenerateProvenanceReport(unsigned)

	// The two reports must be provably different in user-facing fields
	if r1.TrustStatus == r2.TrustStatus {
		t.Errorf("Reports must differentiate signed vs unsigned. Both have TrustStatus=%q", r1.TrustStatus)
	}

	if r1.TrustStatus != "verified" {
		t.Errorf("Expected signed+attested digest to have TrustStatus 'verified', got %q", r1.TrustStatus)
	}

	if r2.TrustStatus != "unsigned" {
		t.Errorf("Expected unsigned digest to have TrustStatus 'unsigned', got %q", r2.TrustStatus)
	}

	if r1.AttestationLevel == r2.AttestationLevel {
		t.Errorf("AttestationLevel should differ between signed and unsigned digests")
	}
}
