package normalize

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"tijeri/internal/models"
	"tijeri/internal/store"
)

// ApplyVEXStatus transitions the finding's status based on its VEX status.
// If VEXStatus is "not_affected", the status transitions to "suppressed_vex".
func ApplyVEXStatus(f *models.Finding) {
	if f.VEXStatus != nil && *f.VEXStatus == "not_affected" {
		f.Status = "suppressed_vex"
	}
}

// GenerateVEXForUnreachable creates a synthetic VEX "not_affected" entry
// when an analyzer like govulncheck proves a vulnerable function is not reachable.
func GenerateVEXForUnreachable(f *models.Finding, isReachable bool) {
	if !isReachable {
		status := "not_affected"
		f.VEXStatus = &status
		
		justification := "vulnerable_code_not_in_execute_path"
		f.VEXJustification = &justification
		
		ApplyVEXStatus(f)
	}
}

// WriteVEXDocument writes an OpenVEX document to the object store.
func WriteVEXDocument(ctx context.Context, f *models.Finding, objStore store.ObjectStore) error {
	status := "not_affected"
	if f.VEXStatus != nil {
		status = *f.VEXStatus
	}
	justification := "vulnerable_code_not_in_execute_path"
	if f.VEXJustification != nil {
		justification = *f.VEXJustification
	}

	doc := map[string]interface{}{
		"@context":  "https://openvex.dev/ns/v0.2.0",
		"@id":       fmt.Sprintf("https://tijeri.internal/vex/%s", f.FindingID),
		"author":    "Tijeri Pipeline",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   1,
		"statements": []map[string]interface{}{
			{
				"vulnerability": f.VulnerabilityID,
				"products": []string{
					f.Component,
				},
				"status":        status,
				"justification": justification,
			},
		},
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}

	// vex/generated/<vulnerability_id>/<sha256(component+justification)>/<generated_at>.json
	hashInput := f.Component + justification
	h := sha256.New()
	h.Write([]byte(hashInput))
	hashStr := hex.EncodeToString(h.Sum(nil))

	key := fmt.Sprintf("vex/generated/%s/%s/%d.json", f.VulnerabilityID, hashStr, time.Now().Unix())
	return objStore.Put(ctx, key, b)
}
