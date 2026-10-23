package secrets

// Provenance represents supply-chain provenance metadata attached to a digest asset (P10-4).
type Provenance struct {
	DigestID     string
	CosignSigned bool
	SLSAAttested bool
	AttestationLevel string // e.g., "slsa_level_3", "none"
}

// ProvenanceReport differentiates signed+attested digests from unsigned ones.
type ProvenanceReport struct {
	DigestID         string `json:"digest_id"`
	Signed           bool   `json:"signed"`
	Attested         bool   `json:"attested"`
	AttestationLevel string `json:"attestation_level"`
	TrustStatus      string `json:"trust_status"` // "verified", "unverified", "unsigned"
}

// GenerateProvenanceReport produces a user-facing report that explicitly differentiates
// signed+attested digests from unsigned ones.
func GenerateProvenanceReport(p Provenance) ProvenanceReport {
	report := ProvenanceReport{
		DigestID:         p.DigestID,
		Signed:           p.CosignSigned,
		Attested:         p.SLSAAttested,
		AttestationLevel: p.AttestationLevel,
	}

	if p.CosignSigned && p.SLSAAttested {
		report.TrustStatus = "verified"
	} else if p.CosignSigned {
		report.TrustStatus = "unverified"
	} else {
		report.TrustStatus = "unsigned"
	}

	return report
}
