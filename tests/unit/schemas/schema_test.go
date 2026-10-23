package schemas_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

type schemaTestCase struct {
	Name     string
	Schema   string
	Valid    []string
	Invalid  []string
}

var testCases = []schemaTestCase{
	{
		Name:   "Finding Schema",
		Schema: "finding.schema.json",
		Valid: []string{
			`{
				"finding_id": "123e4567-e89b-12d3-a456-426614174000",
				"asset_id": "123e4567-e89b-12d3-a456-426614174000",
				"source_tool": "govulncheck",
				"vulnerability_id": "CVE-2025-xxxxx",
				"component": "golang.org/x/crypto",
				"component_version": "0.34.0",
				"cvss": {
					"score": 7.5,
					"version": "3.1",
					"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					"source": "NVD"
				},
				"nvd_enrichment_status": "full",
				"epss": {
					"score": 0.42,
					"percentile": 0.91
				},
				"kev_listed": false,
				"ssvc": "track",
				"vex_status": "not_affected",
				"vex_justification": "vulnerable_code_not_in_execute_path",
				"first_seen": "2026-08-24T09:00:00Z",
				"last_seen": "2026-08-24T09:00:00Z",
				"status": "open",
				"dedup_hash": "abcdef"
			}`,
		},
		Invalid: []string{
			// Missing required field nvd_enrichment_status
			`{
				"finding_id": "123e4567-e89b-12d3-a456-426614174000",
				"asset_id": "123e4567-e89b-12d3-a456-426614174000",
				"source_tool": "govulncheck",
				"vulnerability_id": "CVE-2025-xxxxx",
				"component": "golang.org/x/crypto",
				"component_version": "0.34.0",
				"cvss": null,
				"epss": { "score": 0.42, "percentile": 0.91 },
				"kev_listed": false,
				"ssvc": "track",
				"vex_status": "not_affected",
				"vex_justification": "vulnerable_code_not_in_execute_path",
				"first_seen": "2026-08-24T09:00:00Z",
				"last_seen": "2026-08-24T09:00:00Z",
				"status": "open",
				"dedup_hash": "abcdef"
			}`,
			// Out of enum status
			`{
				"finding_id": "123e4567-e89b-12d3-a456-426614174000",
				"asset_id": "123e4567-e89b-12d3-a456-426614174000",
				"source_tool": "govulncheck",
				"vulnerability_id": "CVE-2025-xxxxx",
				"component": "golang.org/x/crypto",
				"component_version": "0.34.0",
				"cvss": null,
				"nvd_enrichment_status": "full",
				"epss": { "score": 0.42, "percentile": 0.91 },
				"kev_listed": false,
				"ssvc": "track",
				"vex_status": "not_affected",
				"vex_justification": "vulnerable_code_not_in_execute_path",
				"first_seen": "2026-08-24T09:00:00Z",
				"last_seen": "2026-08-24T09:00:00Z",
				"status": "invalid_status_value",
				"dedup_hash": "abcdef"
			}`,
		},
	},
	{
		Name:   "Asset Schema",
		Schema: "asset.schema.json",
		Valid: []string{
			`{
				"asset_id": "123",
				"canonical_name": "server-1",
				"criticality_tier": "mission_critical",
				"exposure": "public",
				"state": "active"
			}`,
		},
		Invalid: []string{
			`{
				"asset_id": "123",
				"canonical_name": "server-1"
			}`,
		},
	},
	{
		Name:   "Vulnerability Schema",
		Schema: "vulnerability.schema.json",
		Valid: []string{
			`{
				"vulnerability_id": "CVE-123",
				"description": "desc",
				"kev_listed": true
			}`,
		},
		Invalid: []string{
			`{
				"vulnerability_id": "CVE-123"
			}`,
		},
	},
	{
		Name:   "Secret Finding Schema",
		Schema: "secret_finding.schema.json",
		Valid: []string{
			`{
				"finding_id": "1",
				"asset_id": "2",
				"pattern_id": "aws-key",
				"file_path": "/etc/passwd",
				"is_verified": true
			}`,
		},
		Invalid: []string{
			`{
				"finding_id": "1"
			}`,
		},
	},
	{
		Name:   "Image Digest Schema",
		Schema: "image_digest.schema.json",
		Valid: []string{
			`{
				"digest": "sha256:123",
				"repository": "repo"
			}`,
		},
		Invalid: []string{
			`{
				"digest": "sha256:123"
			}`,
		},
	},
	{
		Name:   "Attestation Schema",
		Schema: "attestation.schema.json",
		Valid: []string{
			`{
				"subject": "sub",
				"predicate_type": "pred",
				"issuer": "iss",
				"signature": "sig"
			}`,
		},
		Invalid: []string{
			`{
				"subject": "sub"
			}`,
		},
	},
	{
		Name:   "Software Inventory Item Schema",
		Schema: "software_inventory_item.schema.json",
		Valid: []string{
			`{
				"asset_id": "1",
				"component": "comp",
				"version": "1.0",
				"source_channel": "chan"
			}`,
		},
		Invalid: []string{
			`{
				"asset_id": "1"
			}`,
		},
	},
}

func TestSchemas(t *testing.T) {
	schemaDir := "../../../schemas"
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft7

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			path := filepath.Join(schemaDir, tc.Schema)
			absPath, err := filepath.Abs(path)
			if err != nil {
				t.Fatalf("failed to get absolute path: %v", err)
			}
			
			sch, err := compiler.Compile("file://" + absPath)
			if err != nil {
				t.Fatalf("failed to compile schema: %v", err)
			}

			// Test Valid
			for i, validStr := range tc.Valid {
				t.Run(fmt.Sprintf("Valid_%d", i), func(t *testing.T) {
					var validInst interface{}
					if err := json.Unmarshal([]byte(validStr), &validInst); err != nil {
						t.Fatalf("failed to unmarshal valid instance: %v", err)
					}
					if err := sch.Validate(validInst); err != nil {
						t.Errorf("expected valid instance to pass, but failed: %v", err)
					}
				})
			}

			// Test Invalid
			for i, invalidStr := range tc.Invalid {
				t.Run(fmt.Sprintf("Invalid_%d", i), func(t *testing.T) {
					var invalidInst interface{}
					if err := json.Unmarshal([]byte(invalidStr), &invalidInst); err != nil {
						t.Fatalf("failed to unmarshal invalid instance: %v", err)
					}
					if err := sch.Validate(invalidInst); err == nil {
						t.Errorf("expected invalid instance to fail, but passed")
					}
				})
			}
		})
	}
}
